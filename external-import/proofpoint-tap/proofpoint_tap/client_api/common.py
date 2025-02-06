"""Offer common tools for the TAP API."""

import json
from abc import ABC
from logging import getLogger
from typing import TYPE_CHECKING, Any

from aiohttp import (
    BasicAuth,
    ClientConnectionError,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    ContentTypeError,
    TraceConfig,
)
from aiohttp_retry import ListRetry, RetryClient
from proofpoint_tap.client_api.tools import cache_get_response_decorator
from proofpoint_tap.errors import (
    ProofpointAPI404Error,
    ProofpointAPI404NoReasonError,
    ProofpointAPI429Error,
    ProofpointAPIError,
    ProofpointAPIInvalidResponseError,
)
from proofpoint_tap.warnings import PermissiveBaseModel
from pydantic import ValidationError
from yarl import URL

if TYPE_CHECKING:
    from datetime import timedelta
    from types import SimpleNamespace

    from aiohttp import ClientResponse, TraceRequestStartParams
    from pydantic import SecretStr


ResponseModel = PermissiveBaseModel  # Alias

logger = getLogger(__name__)


@cache_get_response_decorator
class BaseClient(  # noqa: B024 # Even though there is no abstract method, it is still an abstract class.
    ABC
):
    """Base class for the TAP API client.

    Notes:
      You can use a local cache to store/load the responses of the API.
      To do so, you need to set the class variable `cache_folder_path` to the path of the cache folder.

      >>> BaseTAPClientChildren.cache_folder_path = pathlib.Path("cache_folder")
      >>> client = BaseTAPClientChildren("http://example.com", "principal", "secret", 1, 1, 1)

    """

    def __init__(
        self: "BaseClient",
        base_url: URL,
        principal: "SecretStr",
        secret: "SecretStr",
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
    ) -> None:
        """Initialize the client.

        Args:
            base_url (URL): The base URL of the TAP API.
            principal (SecretStr): The principal to authenticate with the API.
            secret (SecretStr): The secret to authenticate with the API.
            timeout (timedelta): The timeout for the API requests.
            retry (int): The number of attempt to perform.
            backoff (timedelta): The backoff time between retries.

        """
        # process input
        self.base_url = base_url
        self.auth = BasicAuth(principal.get_secret_value(), secret.get_secret_value())
        timeout_seconds: float = timeout.total_seconds()
        self._timeout = ClientTimeout(
            total=timeout_seconds, sock_connect=timeout_seconds * 5
        )
        self._retry_options = ListRetry(
            timeouts=[backoff.total_seconds()] * retry,
            exceptions=(ClientResponseError, ClientConnectionError),
        )

    def format_get_query(self, path: str, params: dict[str, Any] | None = None) -> URL:
        """Format a query URL.

        Args:
            path (str): The path of the URL to be concatenate with the base_url.
            params (Optional[Dict[str, Any]]): The query parameters.

        Returns:
            URL: The URL object.

        """
        params = params or {}
        return URL.build(
            scheme=self.base_url.scheme,
            host=self.base_url.host or "",
            port=self.base_url.port,
            path=path,
            query=params,
        )

    @property
    def retry_options(self) -> ListRetry:
        """Get the retry options."""
        return self._retry_options

    @retry_options.setter
    def retry_options(self, retry_backoff: tuple[int, "timedelta"]) -> None:
        """Set the retry options."""
        retry, backoff = (
            retry_backoff  # Reminder, only 1 arg can be passed to property.setter
        )
        self._retry_options = ListRetry(
            timeouts=[backoff.total_seconds()] * retry,
            exceptions=(ClientResponseError, ClientConnectionError),
        )

    async def _process_raw_response(self, response: "ClientResponse") -> dict[str, Any]:
        """Process the response from the API.

        Args:
            response (ClientResponse): The raw response from the API.

        Returns:
            dict: The processed response.

        Raises:
            ProofpointAPIError: If the response is invalid.
            ProofpointAPI404Error: If the response is a 404 error. Needed to handle 404 errors.
            ProofpointAPI404NoReasonError: If the response is a 404 error with no reason. Needed to handle 404 errors.
            ProofpointAPI429Error: If the response is a 429 error. Needed to handle rate limiting errors and terminate connector run early.

        """
        try:
            response.raise_for_status()
        except ClientResponseError as e:
            resp_text = await response.text()
            message = f"{e.message} - {resp_text} - query: {response.url}"
            if e.status == 404:
                raise ProofpointAPI404Error(message) from e
            elif e.status == 429:
                raise ProofpointAPI429Error(f"Rate limit reached - {message}") from e
            raise ProofpointAPIError(message) from e
        except AssertionError as e:
            # The API sometimes returns 404 with no reason
            # We then use a specific error to handle this case
            # See TAPCampaignClient.fetch_campaign_ids comments for more details
            if response.status == 404 and response.reason is None:
                raise ProofpointAPI404NoReasonError(
                    f"404 with no reason - query: {response.url}"
                ) from e
        try:
            data = await response.json()
        # Unfortunately sometimes Content-Type Response is text/plain but content is still json
        except ContentTypeError:
            try:
                text_data = await response.text()
                data = json.loads(text_data)
            except json.JSONDecodeError as e:
                logger.error(f"Error while decoding JSON: {e}")
                raise ProofpointAPIError("Error while decoding JSON") from e
        return dict(data)

    @staticmethod
    async def _log_retry(
        session: "ClientSession",  # unused but needed for signature
        trace_config_ctx: "SimpleNamespace",
        params: "TraceRequestStartParams",
    ) -> None:
        """Inner method to log the retry attempt.

        Raises:
            AttributeError: If the trace_request_ctx is not found in the trace_config_ctx.
            KeyError: If the current_attempt is not found in the trace_request_ctx.

        Notes:
            * This method is used as a callback for the trace_config.on_request_start event.

        """
        try:
            current_attempt = trace_config_ctx.trace_request_ctx["current_attempt"]
        except (AttributeError, KeyError) as e:
            logger.error(
                f"Retry must be used with a RetryClient appending 'current_attempt' to : {e}"
            )
            raise e
        if current_attempt > 1:
            logger.warning(
                f"Attempt {current_attempt} for {params.method} {params.url}"
            )

    async def _get(self, query_url: URL) -> "ClientResponse":
        """Perform a GET request."""
        trace_config = TraceConfig()
        trace_config.on_request_start.append(BaseClient._log_retry)

        async with ClientSession(
            auth=self.auth,
            timeout=self._timeout,
            trace_configs=[trace_config],
        ) as session:
            async with RetryClient(
                client_session=session,
                retry_options=self._retry_options,
            ) as retry_client:
                async with retry_client.get(query_url) as resp:
                    _ = await resp.read()  # consume the response
                    return resp

    async def get(
        self, query_url: URL, response_model: type[ResponseModel]
    ) -> ResponseModel:
        """Perform a GET request.

        You should use format_get_query to format the query URL.

        Args:
            query_url (str): The URL to query.
            response_model (type[T]): The model to validate the response.

        Returns:
            (BaseModel-like): The validated response.

        Examples:
            >>> client = BaseTAPClientSubClass(**kwargs)
            >>> query_url = client.format_get_query("path", {"param": "value"})
            >>> response = await client.get(query_url, ResponseModel)

        """
        response = await self._get(query_url)
        data = await self._process_raw_response(response)
        try:
            return response_model.model_validate(data)
        except ValidationError as e:
            logger.debug(f"Received Invalid Data: {data}")
            raise ProofpointAPIInvalidResponseError(
                f"Invalid response from the API: {e}"
            ) from e
