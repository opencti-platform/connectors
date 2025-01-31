# pragma: no cover # do not include tests modules in coverage metrics
"""Test the Campaign Client class module.

This module tests:
    - request params handling methods and errors
    - endpoints success cases
    - Client response errors
    - Model responses

"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aiohttp import ClientResponse, ClientResponseError
from proofpoint_tap.client_api.v2.campaign import CampaignClient
from proofpoint_tap.errors import (
    ProofpointAPI404Error,
    ProofpointAPI404NoReasonError,
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
def campaign_client_instance() -> "CampaignClient":
    """Return a mock CampaignClient instance."""
    client = CampaignClient(
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
    "start_time, end_time, page, size",
    [
        pytest.param(
            datetime.fromisoformat("2020-01-01T00:00:00+00:00"),
            datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
            None,
            None,
            id="interval_too_long",
        ),
        pytest.param(
            datetime.fromisoformat("2023-01-02T00:00:00+00:00"),
            datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
            None,
            None,
            id="end_before_start",
        ),
        pytest.param(
            datetime.fromisoformat("2023-01-01T00:00:00+00:00"),
            datetime.fromisoformat("2023-01-02T00:00:00+00:00"),
            1000,
            None,
            id="size_too_lrge",
        ),
    ],
)
async def test_fetch_campaign_ids_with_wrong_params_raises_error(
    campaign_client_instance, start_time, end_time, page, size
) -> None:
    """Test fetch_campaign_ids method with wrong parameters."""
    # Given a campaign client instance
    # When calling the fetch_campaign_ids method with bad parameters
    # Then a ProofPointAPIRequestParamsError should be raised
    with pytest.raises(ProofPointAPIRequestParamsError):
        await campaign_client_instance.fetch_campaign_ids(
            start_time=start_time, end_time=end_time, page=page, size=size
        )


# test endpoints success cases
@pytest.mark.asyncio
async def test_fetch_campaign_ids_success(campaign_client_instance) -> None:
    """Test fetch_campaign_ids method."""
    # Given a campaign client instance with a _get method that returns a valid response
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value = make_fake_get_client_response()
    campaign_client_instance._get.return_value.status = 200
    campaign_client_instance._get.return_value.json = AsyncMock()
    campaign_client_instance._get.return_value.json.return_value = {
        "campaigns": [{"id": "123", "lastUpdatedAt": "2023-12-12T00:00:00+00:00"}]
    }

    # When calling the fetch_campaign_ids method
    start_time = datetime(2023, 12, 12, tzinfo=timezone.utc)
    end_time = datetime(2023, 12, 12, 12, 0, 0, tzinfo=timezone.utc)
    response = await campaign_client_instance.fetch_campaign_ids(start_time, end_time)

    # Then the response should be a valid CampaignIdsResponse
    assert (  # noqa: S101 # we indeeduse assert in unit tests
        response.campaigns[0].id == "123"
    )
    assert response.campaigns[  # noqa: S101 # we indeed use assert in unit tests
        0
    ].last_updated_at == datetime(  # noqa: S101 # we indeed use assert in unit tests
        2023, 12, 12, tzinfo=timezone.utc
    )


@pytest.mark.asyncio
async def test_fetch_campaign_details_success(campaign_client_instance) -> None:
    """Test fetch_campaign_details method."""
    # Given a campaign client instance with a _get method that returns a valid response
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value = make_fake_get_client_response()
    campaign_client_instance._get.return_value.status = 200
    campaign_client_instance._get.return_value.json = AsyncMock()
    campaign_client_instance._get.return_value.json.return_value = {
        "id": "123",
        "name": "Test Campaign",
        "description": "Test Description",
        "startDate": "2023-12-12T00:00:00+00:00",
        "campaignMembers": [],
    }

    # When calling the fetch_campaign_details method
    response = await campaign_client_instance.fetch_campaign_details("123")

    # Then the response should be a valid CampaignDetailsResponse
    assert response.id == "123"  # noqa: S101 # we indeed use assert in unit tests
    assert (  # noqa: S101 # we indeeduse assert in unit tests
        response.name == "Test Campaign"
    )
    assert (  # noqa: S101 # we indeeduse assert in unit tests
        response.description == "Test Description"
    )
    assert (  # noqa: S101 # we indeeduse assert in unit tests
        response.start_date == datetime(2023, 12, 12, tzinfo=timezone.utc)
    )


@pytest.mark.asyncio
async def test_fetch_campaign_ids_404_no_reason(campaign_client_instance) -> None:
    """Test fetch_campaign_ids method with a 404 status code and no reason."""
    # Given a campaign client instance with a _get method that raises a 404 Error with no Error.reason
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value = make_fake_get_client_response()
    campaign_client_instance._get.return_value.status = 404
    campaign_client_instance._get.return_value.reason = None
    # When calling the fetch_campaign_ids method
    start_time = datetime(2023, 12, 12, tzinfo=timezone.utc)
    end_time = datetime(2023, 12, 12, 12, 0, 0, tzinfo=timezone.utc)

    # Then a ProofpointAPI404NoReasonError should be raised
    with pytest.raises(ProofpointAPI404NoReasonError):
        await campaign_client_instance.fetch_campaign_ids(start_time, end_time)


@pytest.mark.asyncio
async def test_fetch_campaign_ids_404_with_reason(campaign_client_instance) -> None:
    """Test fetch_campaign_ids method with a 404 status code and a reason."""
    # Given a campaign client instance with a _get method that raises a 404 Error with a reason
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value = make_fake_get_client_response()
    campaign_client_instance._get.return_value.status = 404
    campaign_client_instance._get.return_value.reason = "Not Found"
    campaign_client_instance._get.return_value.read = AsyncMock()
    campaign_client_instance._get.return_value.text = AsyncMock()

    # When calling the fetch_campaign_ids method
    start_time = datetime(2023, 12, 12, tzinfo=timezone.utc)
    end_time = datetime(2023, 12, 12, 12, 0, 0, tzinfo=timezone.utc)
    # Then a ProofpointAPI404Error should be raised
    with pytest.raises(ProofpointAPI404Error):
        await campaign_client_instance.fetch_campaign_ids(start_time, end_time)


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 429, 500])
async def test_fetch_campaign_details_4xx_5xx_errors(
    campaign_client_instance, status_code
) -> None:
    """Test fetch_campaign_details method with a 4xx or 5xx status code."""
    # Given a campaign client instance with a _get method that raises a 4xx or 5xx Error
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value.raise_for_status = MagicMock(
        side_effect=ClientResponseError(
            request_info=Mock(),
            history=Mock(),
            status=status_code,
            message="",
            headers=Mock(),
        )
    )

    # When calling the fetch_campaign_details method
    # Then a ProofpointAPIError should be raised
    with pytest.raises(ProofpointAPIError):
        await campaign_client_instance.fetch_campaign_details("123")


@pytest.mark.asyncio
async def test_fetch_campaign_details_with_incorrect_response_data(
    campaign_client_instance,
) -> None:
    """Test fetch_campaign_details method with a 4xx or 5xx status code."""
    # Given a campaign client instance with a _get method that returns a response without the expected data
    campaign_client_instance._get = AsyncMock()
    campaign_client_instance._get.return_value = make_fake_get_client_response()
    campaign_client_instance._get.return_value.status = 200
    campaign_client_instance._get.return_value.json = AsyncMock()
    campaign_client_instance._get.return_value.json.return_value = {}

    # When calling the fetch_campaign_details method
    # Then a ProofpointAPIInvalidResponseError should be raised
    with pytest.raises(ProofpointAPIInvalidResponseError):
        await campaign_client_instance.fetch_campaign_details("123")
