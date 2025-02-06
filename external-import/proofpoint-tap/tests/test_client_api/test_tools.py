# pragma: no cover # do not include tests modules in coverage metrics
"""Test the tools for the BaseTAPClient."""

import pathlib
from unittest.mock import patch

import pytest
from proofpoint_tap.client_api.tools import (
    _convert_get_query_url_to_filepath,
    cache_get_response_decorator,
)
from yarl import URL


class MockBaseTAPClient:
    """Mock BaseTAPClient class."""

    cache_folder_path = pathlib.Path(
        "/tmp"  # noqa: S108 # This path won't be really used
    )

    async def _get(self, query_url: URL):
        return "response"


@cache_get_response_decorator
class MockBaseTAPClientWithCache(MockBaseTAPClient):
    """Mock BaseTAPClient class with cache."""

    pass


@pytest.fixture
def client():
    """Return a mock BaseTAPClient class."""
    return MockBaseTAPClientWithCache()


@pytest.mark.asyncio
async def test_cache_get_response_decorator_load_from_cache(client):
    """Test that the response is loaded from the cache."""
    query_url = URL("https://domain.com/api/item/ids?filter=1")
    filepath = _convert_get_query_url_to_filepath(query_url, client.cache_folder_path)
    with patch(
        "proofpoint_tap.client_api.tools._load_response_from_local_cache",
        return_value="cached_response",
    ) as mock_load:
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.is_file", return_value=True):
                with patch(
                    "pathlib.Path.stat", return_value=type("", (), {"st_size": 1})()
                ):
                    response = await client._get(query_url)
                    mock_load.assert_called_once_with(filepath)
                    assert (  # noqa: S101 # we indeed use assert in unit tests
                        response == "cached_response"
                    )


@pytest.mark.asyncio
async def test_cache_get_response_decorator_store_to_cache(client):
    """Test that the response is stored in the cache."""
    query_url = URL("https://domain.com/api/item/ids?filter=1")
    filepath = _convert_get_query_url_to_filepath(query_url, client.cache_folder_path)
    with patch(
        "proofpoint_tap.client_api.tools._store_response_to_local_cache",
        return_value=filepath,
    ) as mock_store:
        with patch("pathlib.Path.exists", return_value=False):
            with patch("pathlib.Path.mkdir") as mock_mkdir:
                response = await client._get(query_url)
                mock_store.assert_called_once()
                mock_mkdir.assert_called_once()
                assert (  # noqa: S101 # we indeed use assert in unit tests
                    response == "response"
                )


def test_convert_get_query_url_to_filepath(client):
    """Test the _convert_get_query_url_to_filepath function."""
    query_url = URL("https://domain.com/api/item/ids?filter=1")
    filepath = _convert_get_query_url_to_filepath(query_url, client.cache_folder_path)
    assert (  # noqa: S101 # we indeed use assert in unit tests
        filepath == client.cache_folder_path / "api/item/ids/filter__eq__1.pkl"
    )
