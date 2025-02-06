"""Implement adapters for Event Port."""

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Generator, Literal, Optional

from proofpoint_tap.client_api.v2.siem import (
    ClickEvent,
    MessageEvent,
    SIEMClient,
    SIEMResponse,
    ThreatInfo,
)
from proofpoint_tap.ports.event import (
    ClickEventPort,
    EventPort,
    EventsPort,
    EventThreatPort,
    MessageEventPort,
)
from pydantic import IPvAnyAddress

if TYPE_CHECKING:
    from datetime import datetime

    from pydantic import SecretStr
    from yarl import URL


class EventThreatAPIV2(EventThreatPort):
    """Event threat API V2 adapter."""

    def __init__(
        self, threat_name: str, threat_type: str, threat_url: str, classification: str
    ):
        """Initialize the adapter."""
        self._threat_name = threat_name
        self._threat_type = threat_type
        self._threat_url = threat_url
        self._classification = classification

    @classmethod
    def from_threat_info(cls, threat_info: "ThreatInfo") -> "EventThreatAPIV2":
        """Create an adapter from a ThreatInfo object."""
        return cls(
            threat_name=threat_info.threat,
            threat_type=str(
                threat_info.threat_type
            ),  # explicit str cast on literal for mypy compliance
            threat_url=threat_info.threat_url or "",
            classification=threat_info.classification,
        )

    @classmethod
    def from_threat_url(cls, threat_url: str) -> "EventThreatAPIV2":
        """Create an adapter from a threat URL."""
        return cls(
            threat_name="",
            threat_type="",
            threat_url=threat_url,  # in the case of ClickEventAPIV2
            classification="",
        )

    @property
    def name(self) -> str:
        """Get the threat name."""
        return self._threat_name

    @property
    def type(self) -> str:
        """Get the threat type."""
        return self._threat_type

    @property
    def info_url(self) -> str:
        """Get the threat info URL."""
        return self._threat_url

    @property
    def classification(self) -> str:
        """Get the threat classification."""
        return self._classification


class MessageEventAPIV2(MessageEventPort):
    """Message Event API V2 adapter."""

    def __init__(
        self,
        message_event: "MessageEvent",
        type_: Literal["Message Blocked", "Message Delivered"],
    ):
        """Initialize the adapter."""
        self._event = message_event
        self._type = type_

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return self._event.id

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return self._event.guid

    @property
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        return self._type

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return self._event.message_time

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [
            EventThreatAPIV2.from_threat_info(threat_info)
            for threat_info in self._event.threats_info_map
        ]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return self._event.sender

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        return self._event.recipient

    @property
    def queue_id(self) -> str:
        """Get the message queue ID."""
        return self._event.qid

    @property
    def spam_score(self) -> Optional[int]:
        """Get the message spam score."""
        return int(self._event.spam_score) if self._event.spam_score else None

    @property
    def impostor_score(self) -> Optional[int]:
        """Get the message impostor score."""
        return int(self._event.impostor_score) if self._event.impostor_score else None

    @property
    def malware_score(self) -> Optional[int]:
        """Get the message malware score."""
        return int(self._event.malware_score) if self._event.malware_score else None

    @property
    def phish_score(self) -> Optional[int]:
        """Get the message phish score."""
        return int(self._event.phish_score) if self._event.phish_score else None

    @property
    def cluster_name(self) -> Optional[str]:
        """Get the message cluster name."""
        return self._event.cluster

    @property
    def quarantine_folder(self) -> Optional[str]:
        """Get the message quarantine folder."""
        return self._event.quarantine_folder

    @property
    def quarantine_rule(self) -> Optional[str]:
        """Get the message quarantine rule."""
        return self._event.quarantine_rule

    @property
    def policy_routes(self) -> Optional[list[str]]:
        """Get the message policy routes."""
        return self._event.policy_routes

    @property
    def module_runs(self) -> Optional[list[str]]:
        """Get the modules that processed the message."""
        return self._event.modules_run

    @property
    def completely_rewritten(self) -> Optional[bool]:
        """Get the message completely rewritten status."""
        return self._event.completely_rewritten

    @property
    def from_addresses(self) -> Optional[list[str]]:
        """Get the message from addresses."""
        return self._event.from_address

    @property
    def to_addresses(self) -> Optional[list[str]]:
        """Get the message to addresses."""
        return self._event.to_addresses

    @property
    def cc_addresses(self) -> Optional[list[str]]:
        """Get the message cc addresses."""
        return self._event.cc_addresses

    @property
    def subject(self) -> Optional[str]:
        """Get the message subject."""
        return self._event.subject


class ClickEventAPIV2(ClickEventPort):
    """Click Event API V2 adapter."""

    def __init__(
        self,
        click_event: "ClickEvent",
        type_: Literal["Click Blocked", "Click Permitted"],
    ):
        """Initialize the adapter."""
        self._event = click_event
        self._type = type_

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return self._event.message_id

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return self._event.guid  # Common with MessageEventAPIV2

    @property
    def type(
        self,
    ) -> Literal["Click Blocked", "Click Permitted"]:
        """Get the event type."""
        return self._type  # Common with MessageEventAPIV2

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return self._event.click_time

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [EventThreatAPIV2.from_threat_url(self._event.threat_url)]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return self._event.sender  # Common

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipient."""
        return [self._event.recipient]  # Beware here this is not a list this time

    @property
    def click_ip(self) -> IPvAnyAddress:
        """Get the click IP address."""
        return self._event.click_ip

    @property
    def user_agent(self) -> str:
        """Get the click user agent."""
        return self._event.user_agent

    @property
    def url(self) -> str:
        """Get the click URL."""
        return self._event.url

    @property
    def message_id(self) -> Optional[str]:
        """Get the click message ID."""
        return self._event.message_id


class EventsAPIV2(EventsPort):
    """Events API V2 adapter."""

    def __init__(
        self,
        base_url: "URL",
        principal: "SecretStr",
        secret: "SecretStr",
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
    ):
        """Initialize the adapter."""
        self._client = SIEMClient(
            base_url=base_url,
            principal=principal,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
        )

    @staticmethod
    def _chunk_30_minutes_intervals(
        start_time: "datetime", stop_time: "datetime"
    ) -> Generator[tuple["datetime", "datetime"], Any, Any]:
        """Chunk the interval into 30 minutes intervals.

        Example:
            >>> start = datetime(2021,1,1,0,15,0)
            >>> stop = datetime(2021,1,1,3,11,0)
            >>> list(EventsAPIV2._chunk_30_minutes_intervals(start, stop))

        """
        number_of_intervals = int((stop_time - start_time).total_seconds() / 1800) + 1
        for i in range(number_of_intervals):
            if start_time + timedelta(seconds=i * 1800) < stop_time:
                start = start_time + timedelta(seconds=i * 1800)
                stop = min(start_time + timedelta(seconds=(i + 1) * 1800), stop_time)
                yield (start, stop)

    async def _fetch(
        self,
        start_time: "datetime",
        stop_time: "datetime",
        method: Callable[["datetime", "datetime"], Awaitable[SIEMResponse]],
    ) -> SIEMResponse:
        return await method(start_time, stop_time)

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
        """Get the events."""
        method = {
            "all": self._client.fetch_all,
            "issues": self._client.fetch_issues,
            "messages_blocked": self._client.fetch_messages_blocked,
            "messages_delivered": self._client.fetch_messages_delivered,
            "clicks_blocked": self._client.fetch_clicks_blocked,
            "clicks_permitted": self._client.fetch_clicks_permitted,
        }[select]

        async def _coro() -> list[SIEMResponse]:
            # create async list of tasks
            tasks = [
                self._fetch(start_time=start, stop_time=stop, method=method)
                for start, stop in EventsAPIV2._chunk_30_minutes_intervals(
                    start_time=start_time, stop_time=stop_time
                )
            ]
            # gather results (order is preserved)
            return await asyncio.gather(*tasks)

        # flatten and get types
        events_holder: list["EventPort"] = []
        for result in asyncio.run(_coro()):
            for message in result.messages_blocked or []:
                events_holder.append(
                    MessageEventAPIV2(message_event=message, type_="Message Blocked")
                )
            for message in result.messages_delivered or []:
                events_holder.append(
                    MessageEventAPIV2(message_event=message, type_="Message Delivered")
                )
            for click in result.clicks_blocked or []:
                events_holder.append(
                    ClickEventAPIV2(click_event=click, type_="Click Blocked")
                )
            for click in result.clicks_permitted or []:
                events_holder.append(
                    ClickEventAPIV2(click_event=click, type_="Click Permitted")
                )
        return events_holder
