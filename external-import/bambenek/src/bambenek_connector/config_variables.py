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
        print(f"CONFIG FILE PATH = {config_file_path}")
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
        self.duration_period = get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
            required=True,
        )

        self.bambenek_username = get_config_variable(
            env_var="BAMBENEK_USERNAME",
            yaml_path=["bambenek", "username"],
            config=self.load,
            required=True,
        )

        self.bambenek_password = get_config_variable(
            env_var="BAMBENEK_PASSWORD",
            yaml_path=["bambenek", "password"],
            config=self.load,
            required=True,
        )

        bambenek_collections = get_config_variable(
            env_var="BAMBENEK_COLLECTIONS",
            yaml_path=["bambenek", "collections"],
            config=self.load,
            required=True,
            default="phish,malicious,threat",
        )
        self.bambenek_collections = [x.strip() for x in bambenek_collections.split(",")]
