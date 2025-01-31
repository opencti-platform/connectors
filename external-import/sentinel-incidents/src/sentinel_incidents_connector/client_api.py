import json
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout
from urllib3.util.retry import Retry


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define session and update headers when needed
        self.session = requests.Session()

    def set_oauth_token(self):
        try:
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            oauth_data = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }
            response = requests.post(url, data=oauth_data)
            response_json = json.loads(response.text)

            oauth_token = response_json["access_token"]

            self.session.headers.update({"Authorization": oauth_token})
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts.
        """
        retry_strategy = Retry(
            total=5, backoff_factor=2, status_forcelist=[429], raise_on_status=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def query_builder(self, date_str: str) -> requests:
        """
        Constructs the API URL with the necessary query parameters.

        Builds a URL with query parameters to retrieve incidents and associated alerts.
        Filters results according to state, or if the connector is running for the first time, uses `import_start_date`
        from configuration to include only incidents created after that date.

        :param date_str: date in iso 8601 format as a character string.
        :return: A fully constructed URL string for querying incidents.
        """
        base_url = self.config.api_base_url
        incident_path = self.config.incident_path
        params = {"$expand": "alerts", "$filter": f"lastUpdateDateTime ge {date_str}"}
        return requests.Request(
            "GET", f"{base_url}{incident_path}", params=params
        ).prepare()

    def pagination_incidents(self, initial_url: str) -> list[dict]:
        """
        Retrieves all incidents from the API with pagination.

        Iteratively fetches incidents from the initial URL, following pagination links until all incidents have been
        collected. If any request results in an error (retry error, HTTP error, timeout, or connection error), it will
        log the issue and halt further pagination.

        :param initial_url: The initial URL for retrieving incidents.
        :return: A list of all incidents as dictionaries containing mixed data types.
        """
        all_incidents = []
        next_page_url = initial_url

        while next_page_url:
            try:
                response = self.session.get(next_page_url)
                response.raise_for_status()
                data = response.json()
                all_incidents.extend(data.get("value", []))
                next_page_url = data.get("@odata.nextLink")
                if next_page_url:
                    continue
                else:
                    break

            except RetryError as err:
                self.helper.connector_logger.error(
                    "A retry error occurred during incident recovery, maximum retries exceeded for url",
                    {"url": next_page_url, "retry_error": str(err)},
                )
                break
            except HTTPError as err:
                self.helper.connector_logger.error(
                    "A http error occurred during incident recovery",
                    {"url": next_page_url, "http_error": str(err)},
                )
                break
            except Timeout as err:
                self.helper.connector_logger.error(
                    "A timeout error has occurred during incident recovery",
                    {"url": next_page_url, "timeout_error": str(err)},
                )
                break
            except ConnectionError as err:
                self.helper.connector_logger.error(
                    "A connection error occurred during incident recovery",
                    {"url": next_page_url, "connection_error": str(err)},
                )
                break
            except Exception as err:
                self.helper.connector_logger.error(
                    "An unexpected error occurred during the recovery of all incidents",
                    {"url": next_page_url, "error": str(err)},
                )
                break
        return all_incidents

    def get_incidents(self, last_incident_timestamp: int) -> list[dict]:
        """
        Retrieves incidents and manages the API request lifecycle.

        Initializes the retry configuration, builds the API query URL, and retrieves all incidents using pagination.
        Logs any unexpected errors encountered during the retrieval process.

        :return: A list of all incidents as dictionaries containing mixed data types.
        """
        try:
            self.retries_builder()
            convert_date_str = datetime.fromtimestamp(
                last_incident_timestamp, tz=timezone.utc
            ).isoformat()

            request = self.query_builder(convert_date_str)
            all_incidents = self.pagination_incidents(request.url)
            return all_incidents

        except Exception as err:
            self.helper.connector_logger.error(
                "An unknown error occurred during the recovery of all incidents",
                {"error": str(err)},
            )
