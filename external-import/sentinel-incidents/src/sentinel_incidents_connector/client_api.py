import json

import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.headers = None

        self.generate_oauth_token()

    def generate_oauth_token(self):
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
            self.headers = {"Authorization": oauth_token}
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def get_incidents(self) -> list[dict]:
        """
        Get incidents with their alerts from Microsft Sentinel API.
        :return: List of incidents
        """
        try:
            url = (
                f"{self.config.api_base_url}{self.config.incident_path}?$expand=alerts"
            )
            response = requests.get(url, headers=self.headers)
            return response.json()["value"] if "value" in response.json() else []
        except Exception as err:
            self.helper.connector_logger.error(err)
