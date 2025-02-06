"""Tools for the Proofpoint TAP client API."""

import os
import pathlib
import pickle
from logging import getLogger
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import multidict
from aiohttp import ClientResponse
from yarl import URL

if TYPE_CHECKING:
    from aiohttp.tracing import Trace
    from proofpoint_tap.client_api.common import BaseClient

logger = getLogger(__name__)


def _replace(string: str, reverse: bool = False) -> str:
    replacements = {"/": os.sep, "?": "__qm__", "&": "__amp__", "=": "__eq__"}
    if reverse:
        replacements = {v: k for k, v in replacements.items()}
    for _from, _to in replacements.items():
        if _to in string:
            raise ValueError(f"{_to} should not be in URL {string}")
        string = string.replace(_from, _to)
    return string


def _remove_starting_slash(string: str) -> str:
    while string.startswith("/"):
        string = string[1:]
    return string


def _convert_get_query_url_to_filepath(
    query_url: URL, folder_path: pathlib.Path
) -> pathlib.Path:
    """Convert a query URL to a filepath.

    Examples:
        >>> from yarl import URL
        >>> cache_folder_path = pathlib.Path("/tmp")
        >>> query_url = URL("https://domain.com:80/api/item/ids?filter=1")
        >>> _convert_get_query_url_to_filepath(query_url, cache_folder_path).as_posix()
        '/tmp/api/item/ids/filter__eq__1_.pkl'
        >>> query_url = URL("https://domain.com:80/api/item/ids")
        >>> _convert_get_query_url_to_filepath(query_url, cache_folder_path).as_posix()
        '/tmp/api/item/ids.pkl'

    """
    endpoint: str = _remove_starting_slash(query_url.raw_path)
    # query parameters
    query_params = query_url.query
    if (
        query_params
    ):  # case api/item/ids?params=1" => api/item/ids__qm__params__eq__1_.pkl
        # file name is the params with replacements
        encoded = urlencode(query_params)
        filename = f"{_replace(encoded)}.pkl"
        filepath = folder_path / endpoint / filename
    else:  # case api/item/ids => api/item/ids.pkl
        # file name is the last path element
        filepath = folder_path / f"{endpoint}.pkl"
    return filepath


class _PickleClientResponse:
    """Pickle-able version of aiohttp.ClientResponse."""

    class _FakeLoop:
        """Fake loop to avoid pickling issues."""

        def __init__(self: "_PickleClientResponse._FakeLoop") -> None:
            pass

        def get_debug(self: "_PickleClientResponse._FakeLoop") -> bool:
            return False

    def __init__(self, response: "ClientResponse") -> None:
        """Initialize the PickleClientResponse."""
        self.method = response.method
        self.url = response.url
        self.headers = dict(response._headers.items())
        self.status = response.status
        self.body = response._body
        self.writer = response._writer
        self.continue100 = response._continue
        # Can't pickle SSLProtocol._start_shutdown.<locals>.<lambda>
        # Can't pickle CIMultiDictProxy
        self.timer = None  # response._timer
        self.request_info = None  # response.request_info
        self.traces: list["Trace"] = []  # response._traces
        self.loop = None  # response._loop, # response._loop
        self.session = None  # response._session

    def to_response(self) -> "ClientResponse":
        """Convert the PickleClientResponse to a ClientResponse."""
        response = ClientResponse(
            method=self.method,
            url=self.url,
            writer=self.writer,
            continue100=self.continue100,
            timer=self.timer,  # type: ignore[arg-type]
            request_info=self.request_info,  # type: ignore[arg-type]
            traces=self.traces,
            loop=self._FakeLoop(),  # type: ignore[arg-type]
            session=None,  # type: ignore[arg-type]
        )
        response._body = self.body
        response._headers = multidict.CIMultiDict(self.headers)  # type: ignore[assignment]
        response.status = self.status
        return response


def _load_response_from_local_cache(filepath: pathlib.Path) -> ClientResponse:
    """Load a response from a local cache if in .pkl."""
    with open(filepath, "rb") as f:
        response_raw = pickle.load(f)  # noqa: S301  # unsafe by design
        response = _PickleClientResponse.to_response(response_raw)
    return response


def _store_response_to_local_cache(
    response: ClientResponse, filepath: pathlib.Path
) -> pathlib.Path:
    """Store a response to a local cache in .pkl."""
    with open(filepath, "wb") as f:
        pickle.dump(_PickleClientResponse(response), f)
    return filepath


def cache_get_response_decorator(cls: type["BaseClient"]) -> type["BaseClient"]:
    """Decorate BaseClient to cache locally the response of a GET request in pickle file.

    This is based on the BaseClient._get method and BaseClient.cache_folder_path class variable.

    Warnings:
        * This is for dev purpose only.

    Args:
       cls (type[BaseClient]): The class to decorate.

    Returns:
        Callable[..., Any]: The decorator to apply to the class.

    Examples:
        >>> @cache_get_response_decorator
        ... class BaseClientChildren(BaseClient):
        ...     pass
        >>> BaseClientChildren.cache_folder_path = pathlib.Path("/tmp")
        >>> client = BaseClientChildren(**kwargs)
        >>> my_url = client.format_get_query("api/item/ids", {"filter": 1})
        >>> response = client.get(my_url)

    """
    # check if cls has cache_folder_path
    folder_path = getattr(cls, "cache_folder_path", None)
    if folder_path is None:
        return cls

    if not isinstance(folder_path, pathlib.Path):
        raise ValueError(
            f"cache_folder_path should be a pathlib.Path, not {type(folder_path)}"
        )

    # save original async get method
    initial_get = cls._get

    async def altered_get(self: "BaseClient", query_url: URL) -> "ClientResponse":
        filepath = _convert_get_query_url_to_filepath(
            query_url=query_url, folder_path=pathlib.Path(folder_path)
        )
        # early exit if filename > 255 characters
        if len(filepath.name) > 255:
            logger.warning(
                f"Filename {filepath.name} is longer than 255 characters, skipping cache."
            )
            return await initial_get(self, query_url)

        if filepath.exists() and filepath.is_file() and filepath.stat().st_size > 0:
            logger.warning(f"Loading response from cache {filepath}")
            return _load_response_from_local_cache(filepath)
            # Note: we do not delete an eventually corrupted file or invalid response because it might be the wanted usage.
        else:
            response = await initial_get(self, query_url)
            # if needed create folder
            if not filepath.parent.exists():
                filepath.parent.mkdir(parents=True)
                logger.warning(f"Cache folder {filepath.parent} created.")
            filepath = _store_response_to_local_cache(response, filepath)
            logger.warning(f"Storing response to cache {filepath}")
        return response

    cls._get = altered_get  # type: ignore[method-assign]

    return cls
