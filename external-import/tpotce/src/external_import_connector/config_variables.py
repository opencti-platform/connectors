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
        Initialize connector-specific configuration variables from the loaded config.
        :return: None
        """
        # Basic settings
        self.name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], self.load
        ).capitalize()
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
            default=False,
        )
        self.config_marking = get_config_variable(
            "MARKINGS", ["markings"], self.load, isNumber=False, default="TLP:GREEN"
        ).lower()

        # Elasticsearch configurations
        self.elasticsearch_host = get_config_variable(
            "TPOTCE2OCTI_ELK_HOST", ["tpotce2octi", "elk_host"], self.load
        )
        self.username = get_config_variable(
            "TPOTCE2OCTI_WEB_USER_RP", ["tpotce2octi", "web_user_rp"], self.load
        )
        self.password = get_config_variable(
            "TPOTCE2OCTI_WEB_PASSWORD_RP", ["tpotce2octi", "web_password_rp"], self.load
        )

        # Download and notes settings
        self.download_payloads = get_config_variable(
            "TPOTCE2OCTI_DOWNLOAD_PAYLOADS",
            ["tpotce2octi", "download_payloads"],
            self.load,
            default=False,
        )
        self.create_notes = get_config_variable(
            "TPOTCE2OCTI_CREATE_NOTES",
            ["tpotce2octi", "create_notes"],
            self.load,
            default=False,
        )
        self.likelihood_notes = get_config_variable(
            "TPOTCE2OCTI_LIKELIHOOD_NOTES",
            ["tpotce2octi", "likelihood_notes"],
            self.load,
            default=50,
        )

        # Proxy and author settings
        self.proxy_url = get_config_variable(
            "TPOTCE2OCTI_PROXY_URL", ["tpotce2octi", "proxy_url"], self.load, default=""
        )
        self.stix_author = get_config_variable(
            "TPOTCE2OCTI_CREATE_AUTHOR",
            ["tpotce2octi", "create_author"],
            self.load,
            default="Unknown",
        )
        self.stix_labels = get_config_variable(
            "TPOTCE2OCTI_CREATE_LABELS",
            ["tpotce2octi", "create_labels"],
            self.load,
            default="",
        ).split(",")
        self.retrofeed_start_date = get_config_variable(
            "TPOTCE2OCTI_RETROFEED_START_DATE",
            ["tpotce2octi", "retrofeed_start_date"],
            self.load,
            default=None,
        )
