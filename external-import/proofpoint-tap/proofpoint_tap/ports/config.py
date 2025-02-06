# isort: skip_file # Skipping this file to prevent isort from removing type ignore comments for untyped imports
"""Provide interfaces for loading configuration settings."""

import datetime
from abc import ABC, abstractmethod
from functools import wraps
from logging import getLogger
from typing import Any, Callable, Literal, Optional

from pydantic import SecretStr, ValidationError
from yarl import URL

from proofpoint_tap.errors import ConfigLoaderError

# we do not have access to OpenCTI Connector logger as it needs a config to be initialized
_logger = getLogger(__name__)


class ConfigBaseLoader(ABC):  # noqa: B024
    """Base class for configuration loaders."""


def _make_error_handler(message: str, required: bool = True) -> Callable[..., Any]:
    """Make (factory) a decorator to handle validators ValidationError, TypeError and ValueError
    with a custom message.

    Args:
        message(str): Custom message to send to logger when the exception occurs.
        required(bool): If the field is required or not.

    Returns:
        A decorator that wraps a function in a try-except block and raise ConfigLoaderError.

    """

    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def _wrapper(*args: tuple[Any], **kwargs: dict[str, Any]) -> Any:
            try:
                result = func(*args, **kwargs)
                if required and result is None:
                    raise ValueError(f"Field {func.__name__} is required")
                return result
            except (ValidationError, TypeError, ValueError) as exc:
                _logger.error(message)
                raise ConfigLoaderError(message) from exc

        return _wrapper

    return _decorator


class ConfigLoaderOCTIPort(ConfigBaseLoader):
    """Interface for loading OpenCTI dedicated configuration."""

    @property
    @abstractmethod
    def _url(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve OpenCTI URL in config")
    def url(self) -> str:
        """URL for OpenCTI API."""
        return self._url

    @property
    @abstractmethod
    def _token(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve OpenCTI Token in config")
    def token(self) -> SecretStr:
        """Token for OpenCTI API."""
        return SecretStr(self._token)


class ConfigLoaderConnectorPort(ABC):
    """Abstract base class for loading connector dedicated configuration."""

    @property
    @abstractmethod
    def _id(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve connector ID in config")
    def id(self) -> str:
        """Connector ID."""
        return self._id

    @property
    @_make_error_handler("Unable to retrieve connector type in config")
    def type(self) -> Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]:
        """Connector type."""
        return "EXTERNAL_IMPORT"

    @property
    @abstractmethod
    def _name(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve connector name in config")
    def name(self) -> str:
        """Connector name."""
        return self._name

    @property
    @abstractmethod
    def _scope(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve connector scope in config")
    def scope(self) -> str:
        """Connector scope."""
        return self._scope

    @property
    @abstractmethod
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]: ...

    @property
    @_make_error_handler("Unable to retrieve connector log level in config")
    def log_level(self) -> Literal["debug", "info", "warn", "error"]:
        """Connector log level."""
        if self._log_level not in ["debug", "info", "warn", "error"]:
            raise ValueError(
                f"Invalid log level: {self._log_level}. Must be one of 'debug', 'info', 'warn', 'error'"
            )
        return self._log_level

    @property
    @abstractmethod
    def _duration_period(self) -> "datetime.timedelta": ...

    @property
    @_make_error_handler("Unable to retrieve connector duration period in config")
    def duration_period(self) -> "datetime.timedelta":
        """Connector scheduler settings."""
        return self._duration_period

    @property
    @abstractmethod
    def _queue_threshold(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve connector queue threshold in config")
    def queue_threshold(self) -> int:
        """Connector queue max size in Mbytes."""
        return self._queue_threshold if self._queue_threshold is not None else 500

    @property
    @abstractmethod
    def _run_and_terminate(self) -> Optional[bool]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector run-and-terminate flag in config"
    )
    def run_and_terminate(self) -> bool:
        """Connector run-and-terminate flag."""
        return self._run_and_terminate if self._run_and_terminate is not None else False

    @property
    @abstractmethod
    def _send_to_queue(self) -> Optional[bool]: ...

    @property
    @_make_error_handler("Unable to retrieve connector send-to-queue flag in config")
    def send_to_queue(self) -> bool:
        """Connector send-to-queue flag."""
        return self._send_to_queue if self._send_to_queue is not None else True

    @property
    @abstractmethod
    def _send_to_directory(self) -> Optional[bool]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory flag in config"
    )
    def send_to_directory(self) -> bool:
        """Connector send-to-directory flag."""
        return self._send_to_directory if self._send_to_directory is not None else False

    @property
    @abstractmethod
    def _send_to_directory_path(self) -> Optional[str]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory path in config"
    )
    def send_to_directory_path(self) -> str:
        """Connector send-to-directory path."""
        return (
            self._send_to_directory_path
            if self._send_to_directory_path is not None
            else ""
        )

    @property
    @abstractmethod
    def _send_to_directory_retention(self) -> Optional[int]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory retention in config"
    )
    def send_to_directory_retention(self) -> int:
        """Connector send-to-directory retention."""
        return (
            self._send_to_directory_retention
            if self._send_to_directory_retention is not None
            else 7
        )


class ConfigLoaderTAPPort(ABC):
    """Abstract base class for loading dedicated configuration."""

    @property
    @abstractmethod
    def _api_base_url(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve API base URL in config")
    def api_base_url(self) -> URL:
        """Base URL for API."""
        return URL(self._api_base_url)

    @property
    @abstractmethod
    def _api_principal_key(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve API principal key in config")
    def api_principal_key(self) -> SecretStr:
        """Access key for API."""
        return SecretStr(self._api_principal_key)

    @property
    @abstractmethod
    def _api_secret_key(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve API secret key in config")
    def api_secret_key(self) -> SecretStr:
        """Secret key for API."""
        return SecretStr(self._api_secret_key)

    @property
    @abstractmethod
    def _api_timeout(self) -> Optional[datetime.timedelta]: ...

    @property
    @_make_error_handler("Unable to retrieve API timeout in config")
    def api_timeout(self) -> datetime.timedelta:
        """Timeout duration, Default to 30 seconds."""
        return (
            self._api_timeout
            if self._api_timeout is not None
            else datetime.timedelta(seconds=30)
        )

    @property
    @abstractmethod
    def _api_backoff(self) -> Optional["datetime.timedelta"]: ...

    @property
    @_make_error_handler("Unable to retrieve API backoff duration in config")
    def api_backoff(self) -> "datetime.timedelta":
        """Backoff duration, default to 5 seconds."""
        return (
            self._api_backoff
            if self._api_backoff is not None
            else datetime.timedelta(seconds=5)
        )

    @property
    @abstractmethod
    def _api_retries(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve API retry count in config")
    def api_retries(self) -> int:
        """Number of retries, default to 3."""
        return self._api_retries if self._api_retries is not None else 3

    @property
    @abstractmethod
    def _marking_definition(
        self,
    ) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve marking definition in config")
    def marking_definition(
        self,
    ) -> Literal["white", "green", "amber", "amber+strict", "red"]:
        """Marking definition to apply to exported data."""
        definition = self._marking_definition.lower()
        if definition not in ["white", "green", "amber", "amber+strict", "red"]:
            raise ValueError(
                f"Invalid marking definition: {definition}. Must be one of 'white', 'green', 'amber', 'amber+strict', 'red'"
            )
        return definition  # type: ignore[return-value] # Literal is ensure with the if statement above

    # Commented until the product team confirms if it's needed
    # @property
    # @abstractmethod
    # def _export_since(self) -> datetime.datetime: ...

    # @property
    # @_make_error_handler("Unable to retrieve export since in config")
    # def export_since(self) -> datetime.datetime:
    #     """Export since datetime."""
    #     # add utc timezone if naive datetime
    #     dt = self._export_since
    #     if dt.tzinfo is None:
    #         dt = datetime.datetime(
    #             dt.year, dt.month, dt.day, tzinfo=datetime.timezone.utc
    #         )
    #     # compare if datetime in the future
    #     if dt > datetime.datetime.now(datetime.timezone.utc):
    #         raise ValueError("Export since datetime cannot be in the future")
    #     return dt

    @property
    @abstractmethod
    def _export_campaigns(self) -> bool: ...

    @property
    @_make_error_handler("Unable to retrieve export campaigns in config")
    def export_campaigns(self) -> bool:
        """Export campaigns flag."""
        # check one of the export flags is set to True
        if not self._export_campaigns and not self._export_events:
            raise ValueError("At least one of the export flags must be set to True")

        return self._export_campaigns

    @property
    @abstractmethod
    def _export_events(self) -> bool: ...

    @property
    @_make_error_handler("Unable to retrieve export events in config")
    def export_events(self) -> bool:
        """Export events flag."""
        if not self._export_campaigns and not self._export_events:
            raise ValueError("At least one of the export flags must be set to True")
        return self._export_events

    @property
    @abstractmethod
    def _events_type(self) -> Optional[
        Literal[
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ]
    ]: ...

    @property
    @_make_error_handler("Unable to retrieve events type in config")
    def events_type(self) -> Optional[
        Literal[
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ]
    ]:
        """Events type to export."""
        if self.export_events and not self._events_type:
            raise ValueError("Events type must be set when exporting events")
        if self._events_type not in [
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ]:
            raise ValueError(
                f"Invalid events type: {self._events_type}. Must be one of 'all', 'issues', 'messages_blocked', 'messages_delivered', 'clicks_blocked', 'clicks_permitted'"
            )
        return self._events_type


# we assume the abstract is already implemented to keep interface/port paradigm.
class ConfigLoaderPort(ABC):  # noqa: B024
    """Interface for loading configuration settings."""

    def __init__(
        self,
        config_loader_opencti: ConfigLoaderOCTIPort,
        config_loader_connector: ConfigLoaderConnectorPort,
        config_loader_tap: ConfigLoaderTAPPort,
    ):
        """Initialize the configuration loader."""
        self.opencti = config_loader_opencti
        self.connector = config_loader_connector
        self.tap = config_loader_tap

        # run to check mandatory vars are retrieved
        _ = self.to_dict()

    def to_dict(self, token_as_plaintext: bool = False) -> dict[str, Any]:
        """Gather configuration settings and return them as a dictionary."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": (
                    self.opencti.token.get_secret_value()
                    if token_as_plaintext
                    else self.opencti.token
                ),
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "log_level": self.connector.log_level,
                "duration": self.connector.duration_period,
                "queue_threshold": self.connector.queue_threshold,
                "run_and_terminate": self.connector.run_and_terminate,
                "send_to_queue": self.connector.send_to_queue,
                "send_to_directory": self.connector.send_to_directory,
                "send_to_directory_path": self.connector.send_to_directory_path,
                "send_to_directory_retention": self.connector.send_to_directory_retention,
            },
            "tap": {
                "api_base_url": self.tap.api_base_url,
                "api_principal_key": self.tap.api_principal_key,
                "api_secret_key": self.tap.api_secret_key,
                "api_timeout": self.tap.api_timeout,
                "api_backoff": self.tap.api_backoff,
                "api_retries": self.tap.api_retries,
                "marking_definition": self.tap.marking_definition,
                "export_campaigns": self.tap.export_campaigns,
                "export_events": self.tap.export_events,
                "events_type": self.tap.events_type,
            },
        }
