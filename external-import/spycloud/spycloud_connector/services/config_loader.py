import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pycti import get_config_variable
from spycloud_connector.utils.decorators import validate_return_value

if TYPE_CHECKING:
    from spycloud_connector.models.opencti import TLPMarkingLevel
    from spycloud_connector.models.spycloud import (
        BreachRecordSeverity,
        BreachRecordWatchlistType,
    )


SPYCLOUD_SEVERITY_CODES = [2, 5, 20, 25]
SPYCLOUD_WATCHLIST_TYPES = ["email", "domain", "subdomain", "ip"]
OCTI_TLP_LEVELS = ["white", "green", "amber", "amber+strict", "red"]


config_yml_file_path = Path(__file__).parents[2].joinpath("config.yml")
config_yml = (
    yaml.load(open(config_yml_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_yml_file_path)
    else {}
)


class OpenCTIConfig:
    @property
    def url(self) -> str:
        return get_config_variable(
            env_var="OPENCTI_URL",
            yaml_path=["opencti", "url"],
            config=config_yml,
            required=True,
        )

    @property
    def token(self) -> str:
        return get_config_variable(
            env_var="OPENCTI_TOKEN",
            yaml_path=["opencti", "token"],
            config=config_yml,
            required=True,
        )


class ConnectorConfig:
    @property
    def id(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_ID",
            yaml_path=["connector", "id"],
            config=config_yml,
            required=True,
        )

    @property
    def type(self) -> Literal["EXTERNAL_IMPORT"]:
        return "EXTERNAL_IMPORT"

    @property
    def name(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_NAME",
            yaml_path=["connector", "name"],
            config=config_yml,
            required=True,
        )

    @property
    def log_level(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_LOG_LEVEL",
            yaml_path=["connector", "log_level"],
            config=config_yml,
            default="info",
            required=True,
        )

    @property
    def scope(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_SCOPE",
            yaml_path=["connector", "scope"],
            config=config_yml,
            default="spycloud",
            required=True,
        )

    @property
    def duration_period(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=config_yml,
            required=True,
        )


class SpyCloudConfig:
    @property
    def api_base_url(self) -> str:
        raw_url = get_config_variable(
            env_var="SPYCLOUD_API_BASE_URL",
            yaml_path=["spycloud", "api_base_url"],
            config=config_yml,
            required=True,
        )
        return raw_url if raw_url.endswith("/") else f"{raw_url}/"

    @property
    def api_key(self) -> str:
        return get_config_variable(
            env_var="SPYCLOUD_API_KEY",
            yaml_path=["spycloud", "api_key"],
            config=config_yml,
            required=True,
        )

    @property
    @validate_return_value(
        lambda values: all(v in SPYCLOUD_SEVERITY_CODES for v in values)
    )
    def severity_levels(self) -> list["BreachRecordSeverity"]:
        severity_levels_string = get_config_variable(
            env_var="SPYCLOUD_SEVERITY_LEVELS",
            yaml_path=["spycloud", "severity_levels"],
            config=config_yml,
            default="",
            required=False,
        )
        return [
            int(string.strip())
            for string in severity_levels_string.split(",")
            if len(string.strip())
        ]

    @property
    @validate_return_value(
        lambda values: all(v in SPYCLOUD_WATCHLIST_TYPES for v in values)
    )
    def watchlist_types(self) -> list["BreachRecordWatchlistType"]:
        watchlist_types_string = get_config_variable(
            env_var="SPYCLOUD_WATCHLIST_TYPES",
            yaml_path=["spycloud", "watchlist_types"],
            config=config_yml,
            default="",
            required=False,
        )
        return [
            string.strip()
            for string in watchlist_types_string.split(",")
            if len(string.strip())
        ]

    @property
    @validate_return_value(lambda value: value in OCTI_TLP_LEVELS)
    def tlp_level(self) -> "TLPMarkingLevel":
        return get_config_variable(
            env_var="SPYCLOUD_TLP_LEVEL",
            yaml_path=["spycloud", "tlp_level"],
            config=config_yml,
            default="amber+strict",
            required=False,
        )

    @property
    def import_start_date(self) -> datetime:
        import_start_date_string = get_config_variable(
            env_var="SPYCLOUD_IMPORT_START_DATE",
            yaml_path=["spycloud", "import_start_date"],
            config=config_yml,
            default="1970-01-01T00:00:00Z",
            required=False,
        )
        return datetime.fromisoformat(import_start_date_string).replace(
            tzinfo=timezone.utc
        )


class ConfigLoader:
    opencti: OpenCTIConfig = OpenCTIConfig()
    connector: ConnectorConfig = ConnectorConfig()
    spycloud: SpyCloudConfig = SpyCloudConfig()

    def to_dict(self) -> dict[str, Any]:
        """Gather configuration settings and return them as a dictionary."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": self.opencti.token,
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "log_level": self.connector.log_level,
                "duration": self.connector.duration_period,
                # "queue_threshold": self.connector.queue_threshold,
                # "run_and_terminate": self.connector.run_and_terminate,
                # "send_to_queue": self.connector.send_to_queue,
                # "send_to_directory": self.connector.send_to_directory,
                # "send_to_directory_path": self.connector.send_to_directory_path,
                # "send_to_directory_retention": self.connector.send_to_directory_retention,
            },
            "spycloud": {
                "api_base_url": self.spycloud.api_base_url,
                "api_key": self.spycloud.api_key,
                "severity_levels": self.spycloud.severity_levels,
                "watchlist_types": self.spycloud.watchlist_types,
                "import_start_date": self.spycloud.import_start_date,
                "tlp_level": self.spycloud.tlp_level,
            },
        }
