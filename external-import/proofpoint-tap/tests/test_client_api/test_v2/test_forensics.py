# pragma: no cover # do not include tests modules in coverage metrics
"""Test the Forensics Client class module.

This module tests:
    - request params handling methods and errors
    - endpoints success cases
    - Client response errors
    - Model responses

"""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aiohttp import ClientResponse, ClientResponseError
from proofpoint_tap.client_api.v2.forensics import Forensics, ForensicsClient
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
def forensics_client_instance() -> ForensicsClient:
    """Return a mock Client instance."""
    client = ForensicsClient(
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


# Test request formatting
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "threat_id, campaign_id, include_campaign_forensics",
    [
        pytest.param(
            None,
            None,
            None,
            id="no params",
        ),
        pytest.param(
            "threat_id",
            "campaign_id",
            None,
            id="both params",
        ),
        pytest.param(
            None,
            "campaign_id",
            True,
            id="campaign_id_and_include_campaign_forensics",
        ),
    ],
)
async def test_fetch_forensics_with_wrong_params_raises_error(
    forensics_client_instance,
    threat_id,
    campaign_id,
    include_campaign_forensics,
) -> None:
    """Test fetch_forensics method with wrong parameters."""
    # Given a forensics client instance
    # When calling the fetch_forensics method with bad parameters
    # Then a ProofPointAPIRequestParamsError should be raised
    with pytest.raises(ProofPointAPIRequestParamsError):
        await forensics_client_instance.fetch_forensics(
            threat_id=threat_id,
            campaign_id=campaign_id,
            include_campaign_forensics=include_campaign_forensics,
        )


# Test endpoints success cases
@pytest.mark.asyncio
async def fetch_fornsics_success(forensics_client_instance) -> None:
    """Test fetch_forensics method success."""
    # Given a forensics client instance with a _get method that returns a valid response
    forensics_client_instance._get = AsyncMock()
    forensics_client_instance._get.return_value = make_fake_get_client_response()
    forensics_client_instance._get.return_value.status = 200
    forensics_client_instance._get.return_value.json = AsyncMock()
    forensics_client_instance._get.return_value.json.return_value = {
        "generated": "2023-12-12T00:00:00+00:00",
        "reports": [],
    }

    # When calling the fetch_forensics method
    results = await forensics_client_instance.fetch_forensics(
        threat_id="blah",
    )
    # A correct model response should be returned
    assert isinstance(  # noqa: S101 # we indeed use assert in unit tests
        results, Forensics
    )


# test response errors
@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 429, 500])
async def test_fetch_forensics_response_status_error(
    forensics_client_instance, status_code: int
) -> None:
    """Test fetch_forensics method with a 4xx or 5xx status code."""
    # Given a forensics client instance with a _get method that raises a 4xx or 5xx Error
    forensics_client_instance._get = AsyncMock()
    forensics_client_instance._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=status_code,
            message="Message",
            headers=Mock(),
        )
    )
    # When calling the fetch_forensics method
    # Then a ProofpointAPIError should be raised
    with pytest.raises(ProofpointAPIError):
        await forensics_client_instance.fetch_forensics(
            threat_id="blah",
        )


# Test model responses
@pytest.mark.asyncio
async def test_fetch_forensics_model_invalid_response(
    forensics_client_instance,
) -> None:
    """Test fetch_forensics method with an invalid response."""
    # Given a forensics client instance with a _get method that returns an invalid response
    forensics_client_instance._get = AsyncMock()
    forensics_client_instance._get.return_value = make_fake_get_client_response()
    forensics_client_instance._get.return_value.status = 200
    forensics_client_instance._get.return_value.json = AsyncMock()
    forensics_client_instance._get.return_value.json.return_value = {
        "generated": "2023-12-12T00:00:00+00:00",
        "Reports": "whatever",
    }

    # When calling the fetch_forensics method
    # Then a ProofpointAPIInvalidResponseError should be raised
    with pytest.raises(ProofpointAPIInvalidResponseError):
        await forensics_client_instance.fetch_forensics(
            threat_id="blah",
        )
