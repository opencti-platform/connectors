import os

import yaml
from pycti import get_config_variable


class UrlscanConfig:
    def __init__(self):
        """
        Initialize the Urlscan connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        config_file_path = os.path.join(parent_dir, "config.yml")
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

        self.connector_scope = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], self.load
        )

        self.connector_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], self.load
        )

        self.api_key = get_config_variable(
            "URLSCAN_ENRICHMENT_API_KEY", ["urlscan_enrichment", "api_key"], self.load
        )

        self.api_base_url = get_config_variable(
            "URLSCAN_ENRICHMENT_API_BASE_URL",
            ["urlscan_enrichment", "api_base_url"],
            self.load,
        )

        self.import_screenshot = get_config_variable(
            "URLSCAN_ENRICHMENT_IMPORT_SCREENSHOT",
            ["urlscan_enrichment", "import_screenshot"],
            self.load,
            default="true",
        )

        self.visibility = get_config_variable(
            "URLSCAN_ENRICHMENT_VISIBILITY",
            ["urlscan_enrichment", "visibility"],
            self.load,
            default="public",
        )

        self.search_filtered_by_date = get_config_variable(
            "URLSCAN_ENRICHMENT_SEARCH_FILTERED_BY_DATE",
            ["urlscan_enrichment", "search_filtered_by_date"],
            self.load,
            default=">now-1y",
        )

        self.max_tlp = get_config_variable(
            "URLSCAN_ENRICHMENT_MAX_TLP", ["urlscan_enrichment", "max_tlp"], self.load
        )

        self.create_indicator = get_config_variable(
            "URLSCAN_ENRICHMENT_CREATE_INDICATOR",
            ["urlscan_enrichment", "create_indicator"],
            self.load,
            default="true",
        )
