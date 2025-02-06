# pragma: no cover # do not include tests modules in coverage metrics
"""Test the BaseClient class module."""
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aiohttp import ClientResponse, ClientResponseError, ContentTypeError
from proofpoint_tap.client_api.common import BaseClient, ResponseModel
from proofpoint_tap.errors import (
    ProofpointAPI404Error,
    ProofpointAPI404NoReasonError,
    ProofpointAPIError,
)
from pydantic import SecretStr
from yarl import URL


def make_fake_get_client_response() -> ClientResponse:
    """Return a fake ClientResponse object."""
    return ClientResponse(
        method="GET",
        url=URL("/dummy"),
        writer=Mock(),
        continue100=None,
        timer=Mock(),
        request_info=Mock(),
        traces=[],
        loop=Mock(),
        session=Mock(),
    )


@pytest.fixture(scope="function")
def base_client_subclass_instance() -> "BaseClient":
    """Return a mock BaseClient subclass."""

    class BaseClientChildren(BaseClient):
        """Mock BaseClient subclass."""

        pass

    return BaseClientChildren(
        base_url=URL("http://example.com"),
        principal=SecretStr("principal"),
        secret=SecretStr("*****"),  # noqa: S106  # we indeed harcode a secret here...
        timeout=timedelta(seconds=1),
        retry=1,
        backoff=timedelta(seconds=1),
    )


@pytest.mark.asyncio
async def test_404_status_code(base_client_subclass_instance) -> None:
    """Test the get method with a 404 status code."""
    # Given a base client subclass instance with a _get method that raises a 404 Error
    base_client_subclass_instance._get = AsyncMock()
    base_client_subclass_instance._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=404,
            message="Not Found",
            headers=Mock(),
        )
    )
    # When calling the get method
    # Assert a ProofpointAPI404Error is raised
    with pytest.raises(ProofpointAPI404Error):
        await base_client_subclass_instance.get(URL("/dummy"), ResponseModel)


@pytest.mark.asyncio
async def test_404_status_code_no_reason(base_client_subclass_instance) -> None:
    """Test the get method with a 404 status code and no reason."""
    # Given a base client subclass instance with a _get method that raises a 404 Error
    base_client_subclass_instance._get = AsyncMock()
    base_client_subclass_instance._get.return_value = make_fake_get_client_response()
    base_client_subclass_instance._get.return_value.status = 404
    base_client_subclass_instance._get.return_value.reason = None

    # When calling the get method
    # Assert a ProofpointAPI404NoReasonError is raised
    with pytest.raises(ProofpointAPI404NoReasonError):
        await base_client_subclass_instance.get(URL("/dummy"), ResponseModel)


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 404, 429, 500])
async def test_4xx_5xx_status_code(
    base_client_subclass_instance, status_code: int
) -> None:
    """Test the get method with a 4xx or 5xx status code."""
    # Given a base client subclass instance with a _get method that raises a 4xx or 5xx Error
    base_client_subclass_instance._get = AsyncMock()
    base_client_subclass_instance._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=status_code,
            message="Not Found",
            headers=Mock(),
        )
    )

    # When calling the get method
    # Assert a ProofpointAPIError is raised
    with pytest.raises(ProofpointAPIError):
        await base_client_subclass_instance.get(URL("/dummy"), ResponseModel)


@pytest.mark.asyncio
async def test_response_success(base_client_subclass_instance) -> None:
    """Test _process_raw_response with a successful response."""
    # Given a successful response
    response = Mock()
    response.raise_for_status = Mock()
    response.json = AsyncMock(return_value={"key": "value"})
    base_client_subclass_instance._get = AsyncMock(return_value=response)

    # A dummy response model
    class DummyResponseModel(ResponseModel):
        key: str

    # When processing the response
    result = await base_client_subclass_instance.get(URL("/dummy"), DummyResponseModel)

    # Then the result should be the expected dictionary
    assert result.model_dump() == {  # noqa: S101  # we indeed use assert in test
        "key": "value"
    }


@pytest.mark.asyncio
async def test_process_raw_response_invalid_json(base_client_subclass_instance) -> None:
    """Test _process_raw_response with invalid JSON content."""
    # Given a response with invalid JSON content
    response = Mock()
    response.raise_for_status = Mock()
    response.json = AsyncMock(side_effect=ContentTypeError(Mock(), Mock()))
    response.text = AsyncMock(return_value="Invalid JSON")

    # When processing the response
    # Then a ProofpointAPIError should be raised
    with pytest.raises(ProofpointAPIError):
        await base_client_subclass_instance._process_raw_response(response)
