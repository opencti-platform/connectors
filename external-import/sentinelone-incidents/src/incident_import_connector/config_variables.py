import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # SentinelOne Parameters
        self.s1_url = get_config_variable(
            "SENTINELONE_URL", ["sentinelOne", "url"], self.load
        )

        self.s1_api_key = "APIToken " + (
            get_config_variable(
                "SENTINELONE_API_KEY", ["sentinelOne", "api_key"], self.load
            )
        )

        self.s1_account_id = get_config_variable(
            "SENTINELONE_ACCOUNT_ID", ["sentinelOne", "account_id"], self.load
        )

        self.max_api_attempts = int(
            get_config_variable(
                "SENTINELONE_MAX_API_ATTEMPTS",
                ["sentinelOne", "max_api_attempts"],
                self.load,
            )
        )

        self.sign = get_config_variable(
            "SENTINELONE_SEARCH_SIGN", ["sentinelOne", "search_sign"], self.load
        )
