"""Define the Event port.

It provides only the necessary and sufficient methods to be injected in the use cases.
It should then be used by the adapter.
"""

from abc import ABC, abstractmethod
from inspect import getmembers
from typing import TYPE_CHECKING, Literal, Optional

from pydantic import IPvAnyAddress
from pytablewriter import MarkdownTableWriter

if TYPE_CHECKING:
    from datetime import datetime


class _ListableProperties:
    """Listable properties mixin."""

    @classmethod
    def list_property_names(cls) -> list[str]:
        """List all object property name."""
        return [
            i[0] for i in getmembers(cls, predicate=lambda x: isinstance(x, property))
        ]


class EventThreatPort(ABC, _ListableProperties):
    """Event threat port interface."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the threat name."""
        pass

    @property
    @abstractmethod
    def type(self) -> str:
        """Get the threat type."""
        pass

    @property
    @abstractmethod
    def info_url(self) -> str:
        """Get the threat info URL."""
        pass

    @property
    @abstractmethod
    def classification(self) -> str:
        """Get the threat classification."""
        pass

    def __repr(self) -> str:
        """Represent the object as a string."""
        return " - ".join(
            [
                f"{attr} {str(getattr(self, attr))}"
                for attr in self.list_property_names()
            ]
        )

    def __str__(self) -> str:
        """Represent the object as a string."""
        return self.__repr()

    def __repr__(self) -> str:
        """Represent the object as a string."""
        return self.__repr()


class EventPort(ABC, _ListableProperties):
    """Event port interface."""

    @property
    @abstractmethod
    def id(self) -> Optional[str]:
        """Get the event ID."""
        pass

    @property
    @abstractmethod
    def guid(self) -> str:
        """Get the event GUID."""
        pass

    @property
    @abstractmethod
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        pass

    @property
    @abstractmethod
    def time(self) -> "datetime":
        """Get the event time."""
        pass

    @property
    @abstractmethod
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        pass

    @property
    @abstractmethod
    def sender_address(self) -> str:
        """Get the message sender address."""
        pass

    @property
    @abstractmethod
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        pass

    def to_markdown_table(self) -> str:
        """Convert the object instance to a markdown table with 2 columns : Attribute, Value."""
        md = MarkdownTableWriter(
            headers=["Attribute", "Value"],
            value_matrix=[
                [attr, str(getattr(self, attr))] for attr in self.list_property_names()
            ],
        )
        return str(md)


class MessageEventPort(EventPort):
    """Message Event port interface."""

    @property
    @abstractmethod
    def queue_id(self) -> str:
        """Get the message queue ID."""
        pass

    @property
    @abstractmethod
    def spam_score(self) -> Optional[int]:
        """Get the message spam score."""
        pass

    @property
    @abstractmethod
    def impostor_score(self) -> Optional[int]:
        """Get the message impostor score."""
        pass

    @property
    @abstractmethod
    def malware_score(self) -> Optional[int]:
        """Get the message malware score."""
        pass

    @property
    @abstractmethod
    def phish_score(self) -> Optional[int]:
        """Get the message phish score."""
        pass

    @property
    @abstractmethod
    def cluster_name(self) -> Optional[str]:
        """Get the message cluster name."""
        pass

    @property
    @abstractmethod
    def quarantine_folder(self) -> Optional[str]:
        """Get the message quarantine folder."""
        pass

    @property
    @abstractmethod
    def quarantine_rule(self) -> Optional[str]:
        """Get the message quarantine rule."""
        pass

    @property
    @abstractmethod
    def policy_routes(self) -> Optional[list[str]]:
        """Get the message policy routes."""
        pass

    @property
    @abstractmethod
    def module_runs(self) -> Optional[list[str]]:
        """Get the modules that processed the message."""
        pass

    @property
    @abstractmethod
    def completely_rewritten(self) -> Optional[bool]:
        """Get the message completely rewritten status."""
        pass

    @property
    @abstractmethod
    def from_addresses(self) -> Optional[list[str]]:
        """Get the message from addresses."""
        pass

    @property
    @abstractmethod
    def to_addresses(self) -> Optional[list[str]]:
        """Get the message to addresses."""
        pass

    @property
    @abstractmethod
    def cc_addresses(self) -> Optional[list[str]]:
        """Get the message cc addresses."""
        pass

    @property
    @abstractmethod
    def subject(self) -> Optional[str]:
        """Get the message subject."""
        pass


class ClickEventPort(EventPort):
    """Click Event port interface."""

    @property
    @abstractmethod
    def click_ip(self) -> IPvAnyAddress:
        """Get the click IP address."""
        pass

    @property
    @abstractmethod
    def user_agent(self) -> str:
        """Get the click user agent."""
        pass

    @property
    @abstractmethod
    def url(self) -> str:
        """Get the click URL."""
        pass

    @property
    @abstractmethod
    def message_id(self) -> Optional[str]:
        """Get the click message ID."""
        pass


class EventsPort(ABC):
    """Events port interface."""

    @abstractmethod
    def fetch(
        self,
        start_time: "datetime",
        stop_time: "datetime",
        select: Literal[
            "all",
            "issues",
            "messages_blocked",
            "messages_delivered",
            "clicks_blocked",
            "clicks_permitted",
        ],
    ) -> list[EventPort]:
        """Get the message events."""
        pass
