# pragma: no cover # do not include tests modules in coverage metrics
"""Test the ingest incident use case."""


from datetime import datetime, timezone
from typing import Literal, Optional

from proofpoint_tap.domain.use_cases.ingest_incident import IncidentProcessor
from proofpoint_tap.ports.event import (
    ClickEventPort,
    EventThreatPort,
    MessageEventPort,
)
from stix2.v21.base import _STIXBase21


class DummyEventThreatAdapter(EventThreatPort):
    """Dummy event threat adapter."""

    def __init__(self):
        """Initialize the adapter."""
        pass

    @property
    def name(self) -> str:
        """Get the threat name."""
        return "threat_name"

    @property
    def type(self) -> str:
        """Get the threat type."""
        return "url"

    @property
    def info_url(self) -> str:
        """Get the threat info URL."""
        return "http://threat.info"

    @property
    def classification(self) -> str:
        """Get the threat classification."""
        return "active"


class DummyClickEventAdapter(ClickEventPort):
    """Dummy click event adapter."""

    def __init__(self):
        """Initialize the adapter."""
        pass

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return "event_id_123"

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return "guid_456"

    @property
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        return "Click Blocked"

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return datetime.now(tz=timezone.utc)

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [DummyEventThreatAdapter()]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return "sender@example.com"

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        return ["recipient1@example.com", "recipient2@example.com"]

    @property
    def click_ip(self) -> str:
        """Get the click IP address."""
        return "192.168.1.1"

    @property
    def user_agent(self) -> str:
        """Get the click user agent."""
        return "Mozilla/5.0"

    @property
    def url(self) -> str:
        """Get the click URL."""
        return "http://example.com"

    @property
    def message_id(self) -> Optional[str]:
        """Get the click message ID."""
        return "message_id_789"


class DummyMessageEventAdapter(MessageEventPort):
    """Dummy message event adapter."""

    def __init__(self):
        """Initialize the adapter."""
        pass

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return "message_event_id_123"

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return "message_guid_456"

    @property
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        return "Message Delivered"

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return datetime.now(tz=timezone.utc)

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [DummyEventThreatAdapter()]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return "sender@example.com"

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        return ["recipient1@example.com", "recipient2@example.com"]

    @property
    def queue_id(self) -> str:
        """Get the message queue ID."""
        return "queue_id_789"

    @property
    def spam_score(self) -> Optional[int]:
        """Get the message spam score."""
        return 5

    @property
    def impostor_score(self) -> Optional[int]:
        """Get the message impostor score."""
        return 3

    @property
    def malware_score(self) -> Optional[int]:
        """Get the message malware score."""
        return 0

    @property
    def phish_score(self) -> Optional[int]:
        """Get the message phish score."""
        return 50

    @property
    def cluster_name(self) -> Optional[str]:
        """Get the message cluster name."""
        return "cluster_name_123"

    @property
    def quarantine_folder(self) -> Optional[str]:
        """Get the message quarantine folder."""
        return "quarantine_folder_456"

    @property
    def quarantine_rule(self) -> Optional[str]:
        """Get the message quarantine rule."""
        return "quarantine_rule_789"

    @property
    def policy_routes(self) -> Optional[list[str]]:
        """Get the message policy routes."""
        return ["policy_route_1", "policy_route_2"]

    @property
    def module_runs(self) -> Optional[list[str]]:
        """Get the modules that processed the message."""
        return ["module_run_1", "module_run_2"]

    @property
    def completely_rewritten(self) -> Optional[bool]:
        """Get the message completely rewritten status."""
        return False

    @property
    def from_addresses(self) -> Optional[list[str]]:
        """Get the message from addresses."""
        return ["from_address1@example.com", "from_address2@example.com"]

    @property
    def to_addresses(self) -> Optional[list[str]]:
        """Get the message to addresses."""
        return ["to_address1@example.com", "to_address2@example.com"]

    @property
    def cc_addresses(self) -> Optional[list[str]]:
        """Get the message cc addresses."""
        return ["cc_address1@example.com", "cc_address2@example.com"]

    @property
    def subject(self) -> Optional[str]:
        """Get the message subject."""
        return "Test Subject"


def test_incident_processor_can_prcoess_click_event():
    """Test the incident processor can process a click event."""
    # Given a click event adapter
    adapter = DummyClickEventAdapter()
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the entities should be returned
    ## - 1 Incident entity
    assert (  # noqa: S101 # We indeed call assert in unit tests.
        len([entity for entity in entities if entity.__class__.__name__ == "Incident"])
        == 1
    )
    ## - 3 EmailAddress entities (1 sender 2 recipients)
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddress"
            ]
        )
        == 3
    )
    ## - 3 EmailAddressRelatedToIncident relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddressRelatedToIncident"
            ]
        )
        == 3
    )
    ## - 1 Author
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "OrganizationAuthor"
            ]
        )
        == 1
    )
    # - 1 TLP Marking
    assert (  # noqa: S101
        len(
            [entity for entity in entities if entity.__class__.__name__ == "TLPMarking"]
        )
        == 1
    )
    ## Total 9 entities
    assert len(entities) == 9  # noqa: S101

    ## Than can all be converted to stix object
    # all stix2 lib object
    assert all(  # noqa: S101
        isinstance(entity.to_stix2_object(), _STIXBase21) for entity in entities
    )


def test_incident_processor_can_prcoess_message_event():
    """Test the incident processor can process a message event."""
    # Given a message event adapter
    adapter = DummyMessageEventAdapter()
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the entities should be returned
    ## - 1 Incident entity
    assert (  # noqa: S101 # We indeed call assert in unit tests.
        len([entity for entity in entities if entity.__class__.__name__ == "Incident"])
        == 1
    )
    ## - 9 EmailAddress entities (1 sender, 2 recipients, 2 from, 2 to, 2 cc)
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddress"
            ]
        )
        == 9
    )
    ## - 9 EmailAddressRelatedToIncident relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddressRelatedToIncident"
            ]
        )
        == 9
    )
    ## - 1 EmailMessage entity
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailMessage"
            ]
        )
        == 1
    )
    ## - 1 EmailMessageRelatedToIncident relationship
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailMessageRelatedToIncident"
            ]
        )
        == 1
    )
    ## - 1 Author
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "OrganizationAuthor"
            ]
        )
        == 1
    )
    ## - 1 TLP Marking
    assert (  # noqa: S101
        len(
            [entity for entity in entities if entity.__class__.__name__ == "TLPMarking"]
        )
        == 1
    )
    ## Total 23 entities
    assert len(entities) == 23  # noqa: S101

    ## Than can all be converted to stix object
    # all stix2 lib object
    assert all(  # noqa: S101
        isinstance(entity.to_stix2_object(), _STIXBase21) for entity in entities
    )
