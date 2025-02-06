import traceback
import requests
import json
import os
import time
import urllib3
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

# Disable SSL warnings
urllib3.disable_warnings()

class InfobloxThreatDefenseConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.infoblox_api_key = get_config_variable(
            "INFOBLOX_API_KEY",
            ["infoblox", "api_key"],
            config,
        )
        self.infoblox_verify_ssl = get_config_variable(
            "INFOBLOX_VERIFY_SSL", ["infoblox", "verify_ssl"], config, default=True
        )
        self.infoblox_custom_list_id = get_config_variable(
            "INFOBLOX_CUSTOM_LIST_ID",
            ["infoblox", "custom_list_id"],
            config,
        )

    def get_headers(self):
        """Construct headers for Infoblox API requests."""
        return {
            "Authorization": f"Token {self.infoblox_api_key}",
            "Content-Type": "application/json"
        }

    def make_request_with_retries(self, method, url, retries=3, delay=2, **kwargs):
        """Make a request with retries and exponential backoff."""
        for attempt in range(retries):
            try:
                response = requests.request(method, url, verify=self.infoblox_verify_ssl, **kwargs)
                response.raise_for_status()
                return response
            except requests.exceptions.ConnectionError as e:
                self.helper.log_error(f"[ConnectionError] Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
                else:
                    raise
            except requests.exceptions.HTTPError as e:
                self.helper.log_error(f"[HTTPError] {e}")
                raise
            except Exception as e:
                self.helper.log_error(f"[UnexpectedError] {e}")
                raise

    def get_custom_lists(self):
        """Retrieve all custom lists from the Infoblox portal."""
        url = "https://csp.infoblox.com/api/atcfw/v1/named_lists"
        response = self.make_request_with_retries("GET", url, headers=self.get_headers())

        if response.status_code == 200:
            return response.json()
        else:
            self.helper.log_error(f"Failed to retrieve custom lists: {response.status_code} - {response.text}")
            return None

    def update_custom_list(self, list_id, updated_items, operation):
        """Update a custom list with the given items by adding or removing them."""
        url = f"https://csp.infoblox.com/api/atcfw/v1/named_lists/{list_id}"
        response = self.make_request_with_retries("GET", url, headers=self.get_headers())

        try:
            existing_list = response.json().get("results", {})
        except json.JSONDecodeError:
            self.helper.log_error("Failed to decode the response as JSON.")
            return

        if not existing_list.get("id") or not existing_list.get("name"):
            self.helper.log_error("The 'id' or 'name' field is missing in the response. Verify the API response format.")
            return

        existing_items = {item["item"] for item in existing_list.get("items_described", [])}
        updated_items = set(updated_items) if isinstance(updated_items, (list, set)) else {updated_items}

        if operation == "add":
            combined_items = existing_items.union(updated_items)
        elif operation == "remove":
            combined_items = existing_items - updated_items
        else:
            self.helper.log_error("Invalid operation. Use 'add' or 'remove'.")
            return

        payload = {
            "confidence_level": existing_list.get("confidence_level", "HIGH"),
            "description": existing_list.get("description", ""),
            "id": existing_list["id"],
            "items_described": [{"description": "", "item": item} for item in combined_items],
            "name": existing_list["name"],
            "tags": existing_list.get("tags"),
            "threat_level": existing_list.get("threat_level", "LOW"),
            "type": existing_list["type"]
        }

        update_response = self.make_request_with_retries("PUT", url, headers=self.get_headers(), data=json.dumps(payload))

        if update_response.status_code == 201:
            action = "added to" if operation == "add" else "removed from"
            self.helper.log_info(f"Items successfully {action} the custom list: {updated_items}")
        else:
            self.helper.log_error(f"Failed to update the custom list: {update_response.status_code} - {update_response.text}")

    def _process_message(self, msg):
        """Process a message from the OpenCTI stream."""
        time.sleep(5)  # Introduce a delay to avoid rate-limiting
        try:
            data = json.loads(msg.data)["data"]
            main_observable_type = OpenCTIConnectorHelper.get_attribute_in_extension("main_observable_type", data)

            if main_observable_type == "Domain-Name":
                observable_value = OpenCTIConnectorHelper.get_attribute_in_extension("observable_values", data)[0]["value"]

                if (msg.event in ["create", "update"] and not data.get("revoked")):
                    if data.get("type") == "indicator" and data.get("pattern_type", "").startswith("stix"):
                        self.update_custom_list(self.infoblox_custom_list_id, observable_value, "add")
                elif msg.event == "delete" or (msg.event in ["create", "update"] and data.get("revoked")):
                    self.update_custom_list(self.infoblox_custom_list_id, observable_value, "remove")

        except Exception as ex:
            self.helper.log_error(f"[ERROR] Failed processing message: {ex}")
            self.helper.log_error(f"[ERROR] Message data: {msg}")

    def start(self):
        """Start the connector to listen to the OpenCTI stream."""
        self.helper.listen_stream(self._process_message)

if __name__ == "__main__":
    try:
        connector = InfobloxThreatDefenseConnector()
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
