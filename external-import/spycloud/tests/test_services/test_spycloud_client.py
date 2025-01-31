import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from requests import Response
from spycloud_connector.models.spycloud import BreachCatalog, BreachRecord
from spycloud_connector.services import SpycloudClient

TEST_API_BASE_URL = "http://spycloudtest.com"
TEST_API_KEY = "<API_KEY>"


def get_data_sample(file_name):
    file_path = Path(__file__).parents[1].joinpath("data_samples", file_name)
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture
def mock_spycloud_client():
    helper = Mock()

    config = Mock()
    config.spycloud.api_base_url = TEST_API_BASE_URL
    config.spycloud.api_key = TEST_API_KEY

    return SpycloudClient(helper=helper, config=config)


def mock_response(status_code: int, body: dict = None):
    response = Mock(spec=Response)
    response.status_code = status_code
    response.json = lambda: body

    return response


def test_spycloud_client_session(mock_spycloud_client):
    # Given a SpycloudClient instance
    # When accessing session attribute
    # Then a valid Author should be returned
    assert mock_spycloud_client.session is not None
    assert mock_spycloud_client.session.headers is not None
    assert mock_spycloud_client.session.headers["X-API-KEY"] == TEST_API_KEY


# Valid Input Test
@pytest.mark.parametrize(
    "mock_request",
    [
        pytest.param(
            {
                "url": f"{TEST_API_BASE_URL}/breach/catalog/:breach_catalog_id",
                "status_code": 200,
                "response_body": get_data_sample("breach_catalog_api_response.json"),
            },
            id="get_breach_catalog",
        ),
        pytest.param(
            {
                "url": f"{TEST_API_BASE_URL}/breach/data/watchlist",
                "status_code": 200,
                "response_body": get_data_sample("breach_records_api_response.json"),
            },
            id="get_breach_records",
        ),
    ],
)
def test_spycloud_client_request_should_return_data(mock_spycloud_client, mock_request):
    # Given a SpycloudClient instance
    # When calling _request
    with patch(
        "requests.Session.request",
        return_value=mock_response(status_code=200, body=mock_request["response_body"]),
    ):
        data = mock_spycloud_client._request(method="GET", url=mock_request["url"])

    # Then a valid response body should be returned
    assert isinstance(data["cursor"], str) is True
    assert isinstance(data["hits"], int) is True
    assert isinstance(data["results"], list) is True


# Invalid Input Test
@pytest.mark.parametrize(
    "mock_request",
    [
        pytest.param(
            {"url": TEST_API_BASE_URL, "status_code": 403},
            id="forbidden",
        ),
        pytest.param(
            {"url": TEST_API_BASE_URL, "status_code": 404},
            id="not_found",
        ),
        pytest.param(
            {"url": TEST_API_BASE_URL, "status_code": 429},
            id="too_many_requests",
        ),
    ],
)
def test_spycloud_client_request_should_handle_exceptions(
    mock_spycloud_client, mock_request
):
    # Given a SpycloudClient instance
    # When calling _request
    with patch(
        "requests.Session.request",
        return_value=mock_response(status_code=mock_request["status_code"]),
    ):
        data = mock_spycloud_client._request(method="GET", url=mock_request["url"])

    # Then None should be returned
    assert data is None


def test_spycloud_client_get_breach_catalog(mock_spycloud_client):
    # Given a SpycloudClient instance
    # When calling get_breach_catalog method
    with patch(
        "requests.Session.request",
        return_value=mock_response(
            status_code=200,
            body=get_data_sample("breach_catalog_api_response.json"),
        ),
    ):
        breach_catalog = mock_spycloud_client.get_breach_catalog(":breach_catalog_id")

    # Then a valid BreachCatalog instance should be returned
    assert isinstance(breach_catalog, BreachCatalog) is True


def test_spycloud_client_get_breach_records(mock_spycloud_client):
    # Given a SpycloudClient instance
    # When calling get_breach_records method
    with patch(
        "requests.Session.request",
        return_value=mock_response(
            status_code=200,
            body=get_data_sample("breach_records_api_response.json"),
        ),
    ):
        breach_records = mock_spycloud_client.get_breach_records()

    # Then an iterable of BreachRecord instances should be returned
    assert all(isinstance(br, BreachRecord) for br in breach_records) is True
