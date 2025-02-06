# pragma: no cover # do not include tests modules in coverage metrics
"""Test the Threat Client class module.

This module tests:
    - endpoints success cases
    - Client response errors
    - Model responses

"""
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aiohttp import ClientResponse, ClientResponseError
from proofpoint_tap.client_api.v2.threat import ThreatClient, ThreatSummary
from proofpoint_tap.errors import ProofpointAPIError, ProofpointAPIInvalidResponseError
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
def client_instance() -> ThreatClient:
    """Return a mock Client instance."""
    client = ThreatClient(
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


# Test request success cases
@pytest.mark.asyncio
async def test_fetch_threat_summary(client_instance) -> None:
    """Test the get_threat_summary method."""
    # Given a client instance with a _get method that returns a response
    client_instance._get = AsyncMock()
    client_instance._get.return_value = make_fake_get_client_response()
    client_instance._get.return_value.status = 200
    client_instance._get.return_value.json = AsyncMock()
    client_instance._get.return_value.json.return_value = {
        "id": "1234",
        "identifiedAt": "2021-01-01T00:00:00Z",
        "name": "Example Threat",
        "type": "malware",
        "category": "phishing",
        "status": "active",
        "detectionType": "automated",
        "severityScore": 85,
        "attackSpread": 1,
        "notable": True,
        "verticallyTargeted": False,
        "geoTargeted": False,
        "actors": [],
        "families": [],
        "malware": [],
        "techniques": [],
        "brands": [],
    }

    # When calling the get_threat_summary method
    response = await client_instance.fetch_threat_summary(threat_id="1234")
    # Then the response should be a ThreatSummary instance
    assert isinstance(  # noqa: S101 # We indeed call assert in unit tests.
        response, ThreatSummary
    )


# Test Request errors
@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500])
async def test_fetch_threat_summary_with_error(client_instance, status_code) -> None:
    """Test fetch_threat_summary method with a 4xx or 5xx status code."""
    # Given a client instance with a _get method that raises a 4xx or 5xx Error
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
    # Then a ProofpointAPIInvalidResponseError should be raised
    with pytest.raises(ProofpointAPIError):
        await client_instance.fetch_threat_summary(
            threat_id="blah",
        )


# Test model responses
@pytest.mark.asyncio
async def test_fetch_threat_summary_invalid_response(client_instance) -> None:
    """Test fetch_threat_summary method with an invalid response."""
    # Given a client instance with a _get method that returns an invalid response
    client_instance._get = AsyncMock()
    client_instance._get.return_value = make_fake_get_client_response()
    client_instance._get.return_value.status = 200
    client_instance._get.return_value.json = AsyncMock()
    client_instance._get.return_value.json.return_value = {"other_key": "whatever"}
    # When calling the method
    # Then a ProofpointAPIInvalidResponseError should be raised
    with pytest.raises(ProofpointAPIInvalidResponseError):
        await client_instance.fetch_threat_summary(
            threat_id="blah",
        )
