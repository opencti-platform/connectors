# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Implement configuration loaders.

Classes:
    ConfigLoaderEnv: Aggregates all component-specific loaders into a single configuration loader for environment variables.

"""
import datetime
import pathlib
from typing import Any, Literal, Optional

from pycti import (  # type: ignore[import-untyped]
    get_config_variable,  # pycti does not provide stubs
)
from pydantic import TypeAdapter
import yaml

from dotenv import load_dotenv

from proofpoint_tap.ports.config import (
    ConfigBaseLoader,
    ConfigLoaderConnectorPort,
    ConfigLoaderOCTIPort,
    ConfigLoaderPort,
    ConfigLoaderTAPPort,
)


def _get_config_variable_env(env_var: str, required: bool = False) -> Any:
    value = get_config_variable(env_var=env_var, yaml_path=["", ""])
    if value is None and required:
        raise ValueError(f"Environment variable {env_var} is required but not set.")
    # see https://github.com/OpenCTI-Platform/client-python/issues/817
    return value


def _int_none(value: Any) -> Optional[int]:
    return int(value) if value is not None else None


def _bool_none(value: Any) -> Optional[bool]:
    return bool(value) if value is not None else None


### ENV ###


class _BaseLoaderEnv(ConfigBaseLoader):  # pylint: disable=too-few-public-methods
    """Base class for configuration loaders using environment variables."""


class _ConfigLoaderOCTIEnv(ConfigLoaderOCTIPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderOCTIPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)

    @property
    def _url(self) -> str:
        return _get_config_variable_env(env_var="OPENCTI_URL", required=True)  # type: ignore[no-any-return]
        # required=True will raise ValueError exception, we won't return None.

    @property
    def _token(self) -> str:
        return _get_config_variable_env(env_var="OPENCTI_TOKEN", required=True)  # type: ignore[no-any-return]


class _ConfigLoaderConnectorEnv(ConfigLoaderConnectorPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderConnectorPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)

    @property
    def _id(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_ID",
            required=True,
        )

    @property
    def _name(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_NAME",
            required=True,
        )

    @property
    def _scope(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_SCOPE",
            required=True,
        )

    @property
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_LOG_LEVEL", required=True
        )

    @property
    def _duration_period(self) -> datetime.timedelta:
        duration_period_str: str = _get_config_variable_env(
            env_var="CONNECTOR_DURATION_PERIOD",
            required=True,
        )
        return TypeAdapter(datetime.timedelta).validate_strings(duration_period_str)

    @property
    def _queue_threshold(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="CONNECTOR_QUEUE_THRESHOLD", required=False
            )
        )  # isNumber option might return float

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(
                env_var="CONNECTOR_RUN_AND_TERMINATE", required=False
            )
        )

    @property
    def _send_to_queue(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(env_var="CONNECTOR_SEND_TO_QUEUE", required=False)
        )

    @property
    def _send_to_directory(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(
                env_var="CONNECTOR_SEND_TO_DIRECTORY", required=False
            )
        )

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_SEND_TO_DIRECTORY_PATH", required=False
        )

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="CONNECTOR_SEND_TO_DIRECTORY_RETENTION", required=False
            )
        )


class _ConfigLoaderTAPEnv(ConfigLoaderTAPPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderTAPPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)
        ConfigLoaderTAPPort.__init__(self)

    @property
    def _api_base_url(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TAP_API_BASE_URL", required=True
        )

    @property
    def _api_principal_key(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TAP_API_PRINCIPAL", required=True
        )

    @property
    def _api_secret_key(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TAP_API_SECRET", required=True
        )

    @property
    def _api_timeout(self) -> Optional[datetime.timedelta]:
        timeout_str: str | None = _get_config_variable_env(
            env_var="TAP_API_TIMEOUT",
            required=False,
        )
        if timeout_str is not None:
            return TypeAdapter(datetime.timedelta).validate_strings(timeout_str)
        return None

    @property
    def _api_backoff(self) -> Optional[datetime.timedelta]:
        backoff_str: str | None = _get_config_variable_env(
            env_var="TAP_API_BACKOFF",
            required=False,
        )
        if backoff_str is not None:
            return TypeAdapter(datetime.timedelta).validate_strings(backoff_str)
        return None

    @property
    def _api_retries(self) -> Optional[int]:
        retries_str: str | None = _get_config_variable_env(
            env_var="TAP_API_RETRIES",
            required=False,
        )
        if retries_str is not None:
            return int(retries_str)
        return None

    @property
    def _marking_definition(self) -> str:
        return str(
            _get_config_variable_env(
                env_var="TAP_MARKING_DEFINITION",
                required=True,
            )
        )

    # Commented until the product team confirms if it's needed
    # @property
    # def _export_campaign_since(self) -> datetime.datetime:
    #     export_since_str = str(
    #         _get_config_variable_env(
    #             env_var="TAP_EXPORT_SINCE",
    #             required=True,
    #         )
    #     )
    #     return TypeAdapter(datetime.datetime).validate_strings(export_since_str)

    @property
    def _export_campaigns(self) -> bool:
        flag = _bool_none(
            _get_config_variable_env(
                env_var="TAP_EXPORT_CAMPAIGNS",
            )
        )
        if not flag:
            return False
        return flag

    @property
    def _export_events(self) -> bool:
        flag = _bool_none(
            _get_config_variable_env(
                env_var="TAP_EXPORT_EVENTS",
            )
        )
        if not flag:
            return False
        return flag

    @property
    def _events_type(self) -> Optional[
        Literal[
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ]
    ]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TAP_EVENTS_TYPE",
        )


class ConfigLoaderEnv(
    ConfigLoaderPort, _BaseLoaderEnv
):  # pylint: disable=too-few-public-methods
    """Implementation of the ConfigLoaderPort interface using environment variables."""

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        _ = load_dotenv()
        _BaseLoaderEnv.__init__(self)
        ConfigLoaderPort.__init__(
            self,
            config_loader_opencti=_ConfigLoaderOCTIEnv(),
            config_loader_connector=_ConfigLoaderConnectorEnv(),
            config_loader_tap=_ConfigLoaderTAPEnv(),
        )


### CONFIG YAML FOR DEV PURPOSE ###


def _get_yaml_value(
    yaml_file: pathlib.Path, yaml_path: list[str], required: bool
) -> Any:
    # see https://github.com/OpenCTI-Platform/client-python/issues/817
    with open(yaml_file, "r") as file:
        yaml_data = yaml.safe_load(file)
        try:
            return yaml_data[yaml_path[0]][yaml_path[1]]
        except KeyError as e:
            if required is False:
                return None
            else:
                raise ValueError from e


class _BaseLoaderConfigYaml(ConfigBaseLoader):  # pylint: disable=too-few-public-methods
    """Base class for configuration loaders using config.yaml file."""


class _ConfigLoaderOCTIConfigYaml(ConfigLoaderOCTIPort, _BaseLoaderConfigYaml):
    """Implementation of the ConfigLoaderOCTIPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        self.filepath = filepath

    @property
    def _url(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["opencti", "url"], yaml_file=self.filepath, required=True
        )

    @property
    def _token(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["opencti", "token"], yaml_file=self.filepath, required=True
        )


class _ConfigLoaderConnectorConfigYaml(
    ConfigLoaderConnectorPort, _BaseLoaderConfigYaml
):
    """Implementation of the ConfigLoaderConnectorPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        self.filepath = filepath

    @property
    def _id(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "id"], yaml_file=self.filepath, required=True
        )

    @property
    def _name(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "name"], yaml_file=self.filepath, required=True
        )

    @property
    def _scope(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "scope"], yaml_file=self.filepath, required=True
        )

    @property
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "log_level"], yaml_file=self.filepath, required=True
        )

    @property
    def _duration_period(self) -> datetime.timedelta:
        duration_period_str: str = str(
            _get_yaml_value(
                yaml_path=["connector", "duration_period"],
                yaml_file=self.filepath,
                required=True,
            )
        )
        return TypeAdapter(datetime.timedelta).validate_strings(duration_period_str)

    @property
    def _queue_threshold(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["connector", "queue_threshold"],
                yaml_file=self.filepath,
                required=False,
            )
        )  # isNumber option might return float

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "run_and_terminate"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_queue(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_queue"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_directory(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_directory"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return _get_yaml_value(  # type: ignore[no-any-return]
            yaml_path=["connector", "send_to_directory_path"],
            yaml_file=self.filepath,
            required=False,
        )

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_directory_retention"],
                yaml_file=self.filepath,
                required=False,
            )
        )


class _ConfigLoaderTAPConfigYaml(ConfigLoaderTAPPort, _BaseLoaderConfigYaml):
    """Implementation of the ConfigLoaderTAPPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        self.filepath = filepath

    @property
    def _api_base_url(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tap", "api_base_url"], yaml_file=self.filepath, required=True
        )

    @property
    def _api_principal_key(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tap", "api_principal_key"],
            yaml_file=self.filepath,
            required=True,
        )

    @property
    def _api_secret_key(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tap", "api_secret_key"], yaml_file=self.filepath, required=True
        )

    @property
    def _api_timeout(self) -> Optional[datetime.timedelta]:
        timeout_str: str | None = _get_yaml_value(
            yaml_path=["tap", "api_timeout"],
            yaml_file=self.filepath,
            required=False,
        )
        if timeout_str is not None:
            return TypeAdapter(datetime.timedelta).validate_strings(timeout_str)
        return None

    @property
    def _api_backoff(self) -> Optional[datetime.timedelta]:
        backoff_str: str | None = _get_yaml_value(
            yaml_path=["tap", "api_backoff"],
            yaml_file=self.filepath,
            required=False,
        )
        if backoff_str is not None:
            return TypeAdapter(datetime.timedelta).validate_strings(backoff_str)
        return None

    @property
    def _api_retries(self) -> Optional[int]:
        retries_str: str | None = _get_yaml_value(
            yaml_path=["tap", "api_retries"],
            yaml_file=self.filepath,
            required=False,
        )
        if retries_str is not None:
            return int(retries_str)
        return None

    @property
    def _marking_definition(self) -> str:
        return str(
            _get_yaml_value(
                yaml_path=["tap", "marking_definition"],
                yaml_file=self.filepath,
                required=True,
            )
        )

    # Commented until the product team confirms if it's needed
    # @property
    # def _export_campaign_since(self) -> datetime.datetime:
    #     export_since_str = str(
    #         _get_yaml_value(
    #             yaml_path=["tap", "export_campaign_since"],
    #             yaml_file=self.filepath,
    #             required=True,
    #         )
    #     )
    #     return TypeAdapter(datetime.datetime).validate_strings(export_since_str)

    @property
    def _export_campaigns(self) -> bool:
        flag = _bool_none(
            _get_yaml_value(
                yaml_path=["tap", "export_campaigns"],
                yaml_file=self.filepath,
                required=False,
            )
        )
        if not flag:
            return False
        return flag

    @property
    def _export_events(self) -> bool:
        flag = _bool_none(
            _get_yaml_value(
                yaml_path=["tap", "export_events"],
                yaml_file=self.filepath,
                required=False,
            )
        )
        if not flag:
            return False
        return flag

    @property
    def _events_type(self) -> Optional[
        Literal[
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ]
    ]:
        return _get_yaml_value(  # type: ignore[no-any-return]
            yaml_path=["tap", "events_type"],
            yaml_file=self.filepath,
            required=False,
        )


class ConfigLoaderConfigYaml(
    ConfigLoaderPort, _BaseLoaderConfigYaml
):  # pylint: disable=too-few-public-methods
    """Implementation of the ConfigLoaderPort interface using config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        """Initialize the configuration loader."""
        _BaseLoaderConfigYaml.__init__(self)
        ConfigLoaderPort.__init__(
            self,
            config_loader_opencti=_ConfigLoaderOCTIConfigYaml(filepath),
            config_loader_connector=_ConfigLoaderConnectorConfigYaml(filepath),
            config_loader_tap=_ConfigLoaderTAPConfigYaml(filepath),
        )
