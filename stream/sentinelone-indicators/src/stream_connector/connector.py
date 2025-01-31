import re

import requests
from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector

IOC_API_LOCATION = "web/api/v2.1/threat-intelligence/iocs?accountIds="

# The regex pattern for searching for (type,value) pairs in a stix2.1 pattern.
PATTERN_RE = r"\[([\w:-]+(?:\.[\w-]+)?)\s*=\s*'([^']+)'\]"

# Conversions to Type format accepted by SentinelOne API
# Only support these types in S1.
S1_CONVERSIONS = {
    "url:value": "URL",
    "ipv4-addr:value": "IPV4",
    "domain-name:value": "DNS",
    "hostname:value": "DNS",
    "file:hashes.'SHA-256'": "SHA256",
    "file:hashes.MD5": "MD5",
    "file:hashes.'SHA-1'": "SHA1",
}

###bit confused about the conversions here! found these:
# [file:hashes.'SHA-1' = 'a7f075ba37961545ae0a819bda5d2be28618d60d']
# [file:hashes.'SHA-256' = 'b3ad8409d82500e790e6599337abe4d6edf5bd4c6737f8357d19edd82c88b064']
# [file:hashes.'SHA-256' = '326d05c29c46e6ca7f2f1a9b534d8a2ffb98a13f74f8f26fff2057ad1f8e0ca8']


import json

###remove:
import time


class IndicatorStreamConnector:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        self.helper.log_debug("Initialised Connector.")

    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self.check_stream_id()

        except Exception:
            raise ValueError("Cannot process the message")

        # Performing the main process
        # ===========================
        # === Add your code below ===
        # ===========================

        # EXAMPLE
        # Handle creation
        if msg.event == "create":
            # self.helper.connector_logger.info("[CREATE]")
            message_dict = json.loads(msg.data)

            if "creates a Indicator" in message_dict["message"]:
                indicator_id = message_dict["data"]["id"]
                self.helper.log_info(
                    "New indicator to process found with id: {indicator_id}"
                )

                if not self.process_indicator(indicator_id):

                    self.helper.log_error(
                        f"Error, Failed to process Indicator with id: {indicator_id}"
                    )

        # Handle update
        # if msg.event == "update":
        # self.helper.connector_logger.info("[UPDATE]")
        # Do something
        # raise NotImplementedError

        # Handle delete
        # if msg.event == "delete":
        # self.helper.connector_logger.info("[DELETE]")
        # Do something
        # raise NotImplementedError

        # ===========================
        # === Add your code above ===
        # ===========================

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)

    def process_indicator(self, indicator_id):
        """
        Process an OpenCTI Indicator into SentinelOne IOC form and publish it, following:
            Stage 1: retrieve Indicator from OpenCTI
            Stage 2: Extract Type and Value From Stix Pattern
            Stage 3: Create SentinelOne API Payload with this Information
            Stage 4: Send Payload to SentinelOne (upload the ioc)
        """

        try:
            self.helper.log_debug("Attempting to retrieve Indicator from OpenCTI")
            indicator = self.helper.api.indicator.read(id=indicator_id)
            if not indicator:
                self.helper.log_error(
                    f"Error, unable to retrieve Indicator with id {indicator_id} from OpenCTI Instance"
                )
                return False

            self.helper.log_debug("Success, Indicator retrieved")
            self.helper.log_debug("Attempting to extract Type and Value from pattern")

            ioc_type, ioc_value = self.extract_content(indicator["pattern"])
            if (ioc_type, ioc_value) == (None, None):
                self.helper.log_error(
                    "Error, unable to retrieve and format Type and Value from pattern"
                )
                return False

            self.helper.log_info("Success, Type and Value retrieved and formatted.")
            self.helper.log_debug("Attempting to create IOC Payload for SentinelOne")

            payload = self.create_payload(ioc_type, ioc_value, indicator)
            if not payload:
                self.helper.log_error("Error, unable to create Sentinelone Payload.")
                return False

            self.helper.log_info("Success, Sentinelone Payload created.")
            self.helper.log_debug("Attempting to send Payload to SentinelOne")

            if self.send_payload(payload):
                self.helper.log_info(
                    "Success, Payload sent to SentinleOne, IOC uploaded."
                )
                return True
            else:
                self.helper.log_error("Error, unable to send Payload to SentinelOne.")
                return False

        except Exception as e:
            self.helper.log_error(f"Indicator Stream Failed with Exception Error, {e}")
            return False

    def extract_content(self, pattern):
        """
        Extracts the Type and Value from a stix2.1 Pattern. Formats Type in S1 Case.
        """

        match = re.search(PATTERN_RE, pattern)
        if not match:
            self.helper.log_debug(
                "Error, no Type and Value found for the IOC (regex failure)"
            )
        elif match.lastindex != 2:
            self.helper.log_debug(
                "Error, no Type and Value found for the IOC (regex failure)"
            )
            self.helper.log_debug(
                f"regex search attempt resulted in: ({", ".join(match.groups())})"
            )
        else:
            self.helper.log_debug("Success, Type and Value found in pattern.")
            ioc_value = match.group(2).strip('"').strip("]").strip("'")
            try:
                ioc_type = S1_CONVERSIONS[match.group(1)]

                self.helper.log_debug(pattern)

                self.helper.log_debug("Success, Type converted to SentinelOne format.")
                return ioc_type, ioc_value
            except KeyError:
                # Handle unsupported key
                unsupported_type = match.group(1)
                self.helper.log_error(
                    f"Unsupported Type: '{unsupported_type}' found in pattern. Type is not supported by SentinelOne."
                )
            except Exception as e:
                # Keep other exception handling
                self.helper.log_error(f"Error converting Type, Exception Error: {e}")

        return (None, None)

    def create_payload(self, ioc_type, ioc_value, indicator):
        """
        Creates a formatted payload for S1 API post request, excluding fields if they are missing.
        """
        try:
            possible_entries = {
                "name": indicator.get("name"),
                # "category": (
                #    " | ".join(indicator.get("objectLabel", []))
                #    if indicator.get("objectLabel")
                #    else None
                # ),
                "pattern": indicator.get("pattern"),
                "patternType": indicator.get("pattern_type"),
                "source": self.config.connector_name,
                "description": indicator.get("description"),
                "validUntil": indicator.get("valid_until"),
                "externalId": indicator.get("id"),
                "creationTime": indicator.get("created"),
                "creator": indicator.get("creators", [])[0].get("name"),
                "type": ioc_type,
                "value": ioc_value,
                "method": "EQUALS",
            }

            valid_entries = {k: v for k, v in possible_entries.items() if v is not None}

            payload = {
                "data": [valid_entries],
                "filter": {"tenant": False, "accountIds": [self.config.s1_account_id]},
            }
            return json.dumps(payload)

        except Exception as e:
            self.helper.log_error(f"Exception occurred while creating payload: {e}")
            return None

    def send_payload(self, payload, wait_time=1, attempts=0):
        """
        Attempts to send IOC Payload to SentinelOne via API
        """

        def calculate_exponential_delay(last_wait_time):
            """
            Returns a delay between API Requests ('exponential' required by S1)
            very basic for now.
            """
            return last_wait_time * 2

        HEADERS = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.config.s1_api_key,
        }

        try:
            url = (
                self.config.s1_url
                + "/web/api/v2.1/threat-intelligence/iocs?accountIds="
                + self.config.s1_account_id
            )
            response = requests.post(url, headers=HEADERS, data=payload)
            if response.status_code == 429:
                if attempts < self.config.max_api_attempts:
                    new_wait_time = calculate_exponential_delay(wait_time)
                    self.helper.log_debug(
                        f"Too many requests to S1, waiting: {new_wait_time} seconds"
                    )
                    time.sleep(new_wait_time)
                    return self.send_payload(payload, new_wait_time, attempts + 1)
                else:
                    self.helper.log_error(
                        f"Error, unable to send Payload to SentinelOne after: {self.config.max_api_attempts} attempts, please check your configuration."
                    )
                    return False

            if response.status_code != 200:
                self.helper.log_error(
                    f"Error, Request got Response: {response.status_code}"
                )
                self.helper.log_debug(f"URL Used: {url}")
                self.helper.log_debug(
                    f"S1 responded with: {response.text} to {payload}"
                )
                return False

            self.helper.log_debug("Success, Payload sent")
            self.helper.log_info(
                f"IOC External Id: {response.json().get("data",[])[0].get("externalId","unknown")}"
            )
            return True

        except Exception as e:
            self.helper.log_error(f"Exception Error, {e}.")
        return False
