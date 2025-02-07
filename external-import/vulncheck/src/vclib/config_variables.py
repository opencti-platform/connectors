import os
from pathlib import Path

import yaml
from pycti import get_config_variable

from vclib.models.data_source import DataSource


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
        self.scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            self.load,
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CONNECTOR_VULNCHECK_API_BASE_URL",
            ["connector_vulncheck", "api_base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "CONNECTOR_VULNCHECK_API_KEY",
            ["connector_vulncheck", "api_key"],
            self.load,
        )

        self.data_sources = get_config_variable(
            "CONNECTOR_VULNCHECK_DATA_SOURCES",
            ["connector_vulncheck", "data_sources"],
            self.load,
            default=DataSource.get_all_data_source_strings(),
        )
