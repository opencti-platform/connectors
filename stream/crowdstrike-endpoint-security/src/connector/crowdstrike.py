import json

from pycti import OpenCTIConnectorHelper
from services import ConfigCrowdstrike, CrowdstrikeClient, Metrics


class CrowdstrikeConnector:
    """
    Crowdstrike Endpoint Security connector class
    """

    def __init__(self) -> None:
        """
        Initialize the Crowdstrike Endpoint Security Connector
        with necessary configurations
        """
        self.config = ConfigCrowdstrike()
        self.helper = OpenCTIConnectorHelper(self.config.load, True)
        self.client = CrowdstrikeClient(self.helper)
        self.metrics = Metrics(
            self.helper.connect_name,
            self.config.metrics_addr,
            self.config.metrics_port)

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

    @staticmethod
    def _parse_indicator_pattern(pattern):
        return pattern.strip("[]").split(" ")[0]

    def handle_logger_info(self, action: str, data: dict) -> None:
        """
        On action, update connector logger info
        :param action: Action in string
        :param data: Dict of data from stream
        :return: None
        """
        self.helper.connector_logger.info(
            action + " Processing indicator",
            {
                "Indicator ID": self.helper.get_attribute_in_extension("id", data)
            })

    def _process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        :param msg: Message event from stream
        :return: None
        """
        try:
            self.check_stream_id()
            self.metrics.handle_metrics(msg)

            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        if data["type"] == "indicator":
            self.helper.connector_logger.info("Starting to extract data...")

            indicator_pattern = self._parse_indicator_pattern(data["pattern"])
            indicator_value = data["name"]

            # Handle creation
            if msg.event == "create":
                self.handle_logger_info("[CREATE]", data)

            if msg.event == "update":
                self.handle_logger_info("[UPDATE]", data)

            if msg.event == "delete":
                self.handle_logger_info("[DELETE]", data)

    def start(self) -> None:
        """
        Start main execution loop procedure for connector
        """
        self.helper.listen_stream(self._process_message)

        # Start getting metrics if enable_prometheus_metrics is true
        if self.config.enable_prometheus_metrics:
            self.metrics.start_server()
