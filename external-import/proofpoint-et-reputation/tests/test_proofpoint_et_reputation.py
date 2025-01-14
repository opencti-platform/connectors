from unittest.mock import MagicMock

import pytest
from common_fixtures import (
    fixture_data_domainrepdata,
    fixture_data_iprepdata,
    mock_config,
    mock_helper,
)
from connector.services.client_api import ProofpointEtReputationClient
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout


@pytest.mark.parametrize(
    "side_effect, expected_result, fixture_data, data_name",
    [
        (
            None,
            fixture_data_iprepdata,
            "fixture_data_iprepdata",
            "iprepdata",
        ),  # Status code 200 - Success IPv4 Data
        (
            None,
            fixture_data_domainrepdata,
            "fixture_data_domainrepdata",
            "domainrepdata",
        ),  # Status code 200 - Success Domain Name Data
        (
            RetryError(
                "Max retries exceeded"
            ),  # Status Code 429, 500, 502, 503, 504 - Error
            {
                "error": "Max retries exceeded",
                "message": "[CONNECTOR-API] A retry error occurred during data recovery, maximum retries exceeded for url",
            },
            "fixture_data_iprepdata",
            "iprepdata",
        ),
        (
            HTTPError("HTTP error occurred"),  # Status code 400, 404, 500 - Error
            {
                "error": "HTTP error occurred",
                "message": "[CONNECTOR-API] A http error occurred during data recovery",
            },
            "fixture_data_iprepdata",
            "iprepdata",
        ),
        (
            Timeout("Request timed out"),  # Status code 504 - Error
            {
                "error": "Request timed out",
                "message": "[CONNECTOR-API] A timeout error has occurred during data recovery",
            },
            "fixture_data_iprepdata",
            "iprepdata",
        ),
        (
            ConnectionError("Failed to establish a connection"),  # Status - Error
            {
                "error": "Failed to establish a connection",
                "message": "[CONNECTOR-API] A connection error occurred during data recovery",
            },
            "fixture_data_iprepdata",
            "iprepdata",
        ),
        (
            Exception("Unexpected error"),  # Status - Error
            {
                "error": "Unexpected error",
                "message": "[CONNECTOR-API] An unexpected error occurred during the recovery of all data",
            },
            "fixture_data_iprepdata",
            "iprepdata",
        ),
    ],
    ids=[
        "--FetchData--Success-iprepdata",
        "--FetchData--Success-domainrepdata",
        "--MaxRetriesExceeded--Failure",
        "--HTTPError--ServerError",
        "--TimeoutError--Failure",
        "--ConnectionError--NoConnection",
        "--ExceptionError--Failure",
    ],
)
def test_fetch_data(
    mocker,
    side_effect,
    expected_result,
    fixture_data,
    data_name,
    request,
    mock_helper,
    mock_config,
):
    """
    Test fetch_data with different error scenarios and a success case.
    """
    client = ProofpointEtReputationClient(mock_helper, mock_config)

    if side_effect is None:
        data = request.getfixturevalue(fixture_data)
        mock_fetch = mocker.patch(
            "requests.Session.send",
            return_value=MagicMock(status_code=200, json=lambda: data),
        )
        result = client.fetch_data(reputation_list_entity=data_name)
        print(f"Fetched data for {fixture_data}: {result}")
        assert result == data
        mock_fetch.assert_called_once()
    else:
        mock_fetch = mocker.patch("requests.Session.send", side_effect=side_effect)
        result = client.fetch_data(reputation_list_entity=data_name)
        print(f"Exception triggered {result}")
        assert result == expected_result
        mock_fetch.assert_called_once()
