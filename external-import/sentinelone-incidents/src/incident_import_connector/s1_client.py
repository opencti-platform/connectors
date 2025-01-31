import time

import requests

INCIDENTS_API_LOCATION = "web/api/v2.1/private/threat-groups?limit=50&sortBy=createdAt&sortOrder=desc&accountIds="
INCIDENT_NOTES_API_LOCATION_TEMPLATE = "web/api/v2.1/threats/{incident_id}/notes?limit=1000&sortBy=createdAt&sortOrder=desc"
INCIDENT_API_LOCATION_TEMPLATE = "web/api/v2.1/private/threats/{incident_id}/analysis"


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

    def get_request(self, url, data={}, wait_time=1, attempts=0):
        def calculate_exponential_delay(last_wait_time):
            """
            Returns a delay between API Requests ('exponential' required by S1)
            very basic for now.
            """
            return last_wait_time * 2

        HEADERS = {
            "Accept": "application/json",
            "Authorization": self.config.s1_api_key,
        }
        try:
            response = requests.request(
                "GET", url, headers=HEADERS, data=data, timeout=30
            )
            if response.status_code == 429:
                if attempts < self.config.max_calls:
                    new_wait_time = calculate_exponential_delay(wait_time)
                    self.helper.log_debug(
                        f"Rate limit hit. Retrying in {new_wait_time} seconds..."
                    )
                    time.sleep(new_wait_time)
                    return self.get_request(url, data, new_wait_time, attempts + 1)
                else:
                    self.helper.log_error(
                        "Error, request to S1 API exceeded max attempts."
                    )
                    return None

            elif response.status_code != 200:
                self.helper.log_error(
                    f"Error, Request got Response: {response.status_code}"
                )
                self.helper.log_debug(f"URL Used: {url}")
                self.helper.log_debug(f"Headers Used: {HEADERS}")
                self.helper.log_debug(f"S1 responded with: {response.text}")
                return None

            return response.json().get("data", None)

        except requests.RequestException as err:
            error_msg = "[S1_API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {url}, "error": {str(err)}}
            )
            return None

    def fetch_incidents(self):
        try:
            url = (
                self.config.s1_url + INCIDENTS_API_LOCATION + self.config.s1_account_id
            )
            incidents = self.get_request(url)
            if type(incidents) is str:
                return incidents
            return [inc.get("threatInfo", {}).get("threatId") for inc in incidents]
        except Exception as err:
            self.helper.connector_logger.error(err)

    def retreive_incident(self, incident_id):
        try:
            url = self.config.s1_url + INCIDENT_API_LOCATION_TEMPLATE.format(
                incident_id=incident_id
            )
            return self.get_request(url)
        except Exception as err:
            self.helper.connector_logger.error(err)

    def retreive_incident_notes(self, incident_id):
        try:
            url = self.config.s1_url + INCIDENT_NOTES_API_LOCATION_TEMPLATE.format(
                incident_id=incident_id
            )
            return self.get_request(url)
        except Exception as err:
            self.helper.connector_logger.error(err)
