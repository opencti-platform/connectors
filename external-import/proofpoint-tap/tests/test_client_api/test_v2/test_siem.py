# pragma: no cover # do not include tests modules in coverage metrics
"""Test the SIEM Client class module.

This module tests:
    - request params handling methods and errors
    - endpoints success cases
    - Client response errors
    - Model responses

"""
from datetime import datetime, timedelta, timezone
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aiohttp import ClientResponse, ClientResponseError
from aiohttp_retry import Any
from proofpoint_tap.client_api.v2.siem import SIEMClient, SIEMResponse
from proofpoint_tap.errors import (
    ProofpointAPIError,
    ProofpointAPIInvalidResponseError,
    ProofPointAPIRequestParamsError,
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
def client_instance() -> SIEMClient:
    """Return a mock Client instance."""
    client = SIEMClient(
        base_url=URL("http://example.com"),
        principal=SecretStr("principal"),
        secret=SecretStr("*****"),  # noqa: S106  # we indeed harcode a secret here...
        timeout=timedelta(seconds=1),
        retry=1,
        backoff=timedelta(seconds=1),
    )
    # For safety, we deactivate _get method.
    client._get = AsyncMock()
    return client


def mark_parametrize_all_public_methods(func: Callable[..., Any]) -> Callable[..., Any]:
    """Use to factorize mark.parametrize to decorate test with a prarmetrize for all public methods."""
    return pytest.mark.parametrize(
        "method_name",
        [
            "fetch_clicks_blocked",
            "fetch_clicks_permitted",
            "fetch_messages_blocked",
            "fetch_messages_delivered",
            "fetch_issues",
            "fetch_all",
        ],
    )(func)


# Test request formatting
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "start_time, end_time",
    [
        pytest.param(
            datetime.now(timezone.utc) - timedelta(hours=170),
            datetime.now(timezone.utc) - timedelta(hours=199),
            id="interval too old",
        ),
        pytest.param(
            datetime.now(timezone.utc) - timedelta(hours=48),
            datetime.now(timezone.utc) - timedelta(hours=46),
            id="interval too wide",
        ),
        pytest.param(
            datetime.now(timezone.utc) - timedelta(minutes=30),
            datetime.now(timezone.utc) + timedelta(minutes=10),
            id="interval in the future",
        ),
    ],
)
@mark_parametrize_all_public_methods
async def test_request_params_errors(
    client_instance: SIEMClient,
    start_time: datetime,
    end_time: datetime,
    method_name: str,
) -> None:
    """Test request params errors."""
    # Given a client instance
    # And wrong request params
    # When the public method is called
    public_method = getattr(client_instance, method_name)
    # Then a ProofPointAPIRequestParamsError is raised
    with pytest.raises(ProofPointAPIRequestParamsError):
        _ = await public_method(start_time=start_time, end_time=end_time)


# Test success cases
@pytest.mark.asyncio
@mark_parametrize_all_public_methods
async def test_success_cases(client_instance: SIEMClient, method_name: str) -> None:
    """Test success cases."""
    # Given a client instance
    # And a _get method that returns a response
    client_instance._get = AsyncMock()
    client_instance._get.return_value = make_fake_get_client_response()
    client_instance._get.return_value.status = 200
    client_instance._get.return_value.json = AsyncMock()
    client_instance._get.return_value.json.return_value = {
        "queryEndTime": "2025-01-10T10:00:00Z",
        "clicksPermitted": [],
        "clicksBlocked": [],
        "messagesDelivered": [],
        "messagesBlocked": [],
    }
    # When calling the public method
    public_method = getattr(client_instance, method_name)
    response = await public_method(
        start_time=datetime.now(timezone.utc) - timedelta(minutes=60),
        end_time=datetime.now(timezone.utc) - timedelta(minutes=30),
    )
    # Then the response should be a SIEMResponse instance
    assert isinstance(  # noqa: S101 # We indeed call assert in unit tests.
        response, SIEMResponse
    )
    # And the response should contain the expected data
    assert all(  # noqa: S101 # We indeed call assert in unit tests.
        part == []
        for part in (
            response.clicks_permitted,
            response.clicks_blocked,
            response.messages_delivered,
            response.messages_blocked,
        )
    )


# test response errors
@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 429, 500])
@mark_parametrize_all_public_methods
async def test_response_errors(
    client_instance: SIEMClient, status_code: int, method_name: str
) -> None:
    """Test response errors."""
    # Given a client instance
    # And a _get method that raises a 4xx or 5xx Error
    client_instance._get = AsyncMock()
    client_instance._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=status_code,
            message="Message",
            headers=Mock(),
        )
    )
    # When calling the method
    # Then a ProofPointAPIError should be raised
    with pytest.raises(ProofpointAPIError):
        _ = await client_instance.fetch_all(
            start_time=datetime.now(timezone.utc) - timedelta(minutes=60),
            end_time=datetime.now(timezone.utc) - timedelta(minutes=30),
        )


# Test model responses
@pytest.mark.asyncio
@mark_parametrize_all_public_methods
async def test_model_responses(client_instance: SIEMClient, method_name: str) -> None:
    """Test model responses."""
    # Given a client instance with a _get method that returns an invalid response
    client_instance._get = AsyncMock()
    client_instance._get.return_value = make_fake_get_client_response()
    client_instance._get.return_value.status = 200
    client_instance._get.return_value.json = AsyncMock()
    client_instance._get.return_value.json.return_value = {"other_key": "whatever"}
    # When calling the method
    # Then a ProofpointAPIInvalidResponseError should be raised
    with pytest.raises(ProofpointAPIInvalidResponseError):
        _ = await getattr(client_instance, method_name)(
            start_time=datetime.now(timezone.utc) - timedelta(minutes=60),
            end_time=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
