# pragma: no cover # do not include tests modules in coverage metrics
"""Test the ingest report use case."""

from datetime import datetime, timezone

from proofpoint_tap.domain.use_cases.ingest_report import ReportProcessor
from proofpoint_tap.ports.campaign import CampaignPort, ObservedDataPort
from stix2.v21.base import _STIXBase21


class FakeObservedData(ObservedDataPort):
    """Fake observed data implementation."""

    def __init__(self, type_: str, value: str, observed_at: datetime):
        """Initialize a dummy observed data instance."""
        self._type = type_
        self._value = value
        self._observed_at = observed_at

    @property
    def type_(self) -> str:
        """Get the observed data type."""
        return self._type

    @property
    def value(self) -> str:
        """Get the observed data value."""
        return self._value

    @property
    def observed_at(self) -> "datetime":
        """Get the observed data datetime."""
        return self._observed_at


class DummyCampaign(CampaignPort):
    """Dummy campaign implementation."""

    def __init__(
        self,
        name: str,
        start_datetime: datetime,
        description: str,
        actor_names: list[str],
        malware_names: list[str],
        technique_names: list[str],
        observed_data: list[FakeObservedData],
        targeted_brand_names: list[str],
    ):
        """Initialize a dummy campaign instance."""
        self._name = name
        self._start_datetime = start_datetime
        self._description = description
        self._actor_names = actor_names
        self._malware_names = malware_names
        self._technique_names = technique_names
        self._targeted_brand_names = targeted_brand_names
        self._observed_data = observed_data

    @property
    def name(self) -> str:
        """Get the name of the campaign."""
        return self._name

    @property
    def start_datetime(self) -> "datetime":
        """Get the start datetime of the campaign."""
        return self._start_datetime

    @property
    def description(self) -> str:
        """Get the description of the campaign."""
        return self._description

    @property
    def actor_names(self) -> list[str]:
        """Get the actor names of the campaign."""
        return self._actor_names

    @property
    def malware_names(self) -> list[str]:
        """Get the malware names of the campaign."""
        return self._malware_names

    @property
    def malware_family_names(self) -> list[str]:
        """Get the malware family names of the campaign."""
        return self._malware_names

    @property
    def technique_names(self) -> list[str]:
        """Get the technique names of the campaign."""
        return self._technique_names

    @property
    def targeted_brand_names(self) -> list[str]:
        """Get the targeted brand names of the campaign."""
        return self._targeted_brand_names

    @property
    def observed_data(self) -> list[FakeObservedData]:
        """Get the observed data of the campaign."""
        return self._observed_data


def test_ingest_campaign_use_case_success():
    """Test the ingest report use case with a campaign."""
    # Given :
    # - a dummy campaign instance
    campaign = DummyCampaign(
        name="Campaign 1",
        start_datetime=datetime.now(timezone.utc),
        description="Campaign description",
        actor_names=["actor1", "actor2"],
        malware_names=["malware1", "malware2"],
        technique_names=["technique1", "technique2"],
        observed_data=[
            FakeObservedData(
                type_="url",
                value="http://example.com",
                observed_at=datetime.now(timezone.utc),
            ),
            FakeObservedData(
                type_="ip", value="127.0.0.1", observed_at=datetime.now(timezone.utc)
            ),
        ],
        targeted_brand_names=["brand1", "brand2"],
    )
    # When running the report processor on the campaign
    processor = ReportProcessor(tlp_marking_name="white")
    entities = processor.run_on(campaign)

    # Then expected generated entities should be returned and stix serializable
    # - 1 report entity
    assert (  # noqa: S101 # We indeed call assert in unit tests.
        len([entity for entity in entities if entity.__class__.__name__ == "Report"])
        == 1
    )
    # - 1 obervable and its indicator entities (only URL handled for now)
    assert (  # noqa: S101
        len([entity for entity in entities if entity.__class__.__name__ == "Url"]) == 1
    )
    assert (  # noqa: S101
        len([entity for entity in entities if entity.__class__.__name__ == "Indicator"])
        == 1
    )
    # - 2 intrusion sets
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IntrusionSet"
            ]
        )
        == 2
    )
    # - 2 malware entities
    assert (  # noqa: S101
        len([entity for entity in entities if entity.__class__.__name__ == "Malware"])
        == 2
    )
    # - 2 attack pattern entities
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "AttackPattern"
            ]
        )
        == 2
    )
    # - 2 targeted Organizations
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "TargetedOrganization"
            ]
        )
        == 2
    )
    # - 1 Author
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "OrganizationAuthor"
            ]
        )
        == 1  # noqa: S101
    )
    # 4 - IntrusionSetUsesMalwareRelationship
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IntrusionSetUsesMalware"
            ]
        )
        == 4
    )
    # - 4 IntrusionSetUsesAttackPattern relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IntrusionSetUsesAttackPattern"
            ]
        )
        == 4
    )

    # - 2 IndicatorIndicatesMalware relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IndicatorIndicatesMalware"
            ]
        )
        == 2
    )

    # - 2 IndicatorIndicatesIntrusionSet relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IndicatorIndicatesIntrusionSet"
            ]
        )
        == 2
    )

    # - 4 IntrusionSetTargetsOrganization relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IntrusionSetTargetsOrganization"
            ]
        )
        == 4
    )
    # - 1 Indicator Based on Observable relationships (only URL handled for now)
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "IndicatorBasedOnObservable"
            ]
        )
        == 1
    )
    # - 1 TlpMarking Entity
    assert (  # noqa: S101
        len(
            [entity for entity in entities if entity.__class__.__name__ == "TLPMarking"]
        )
        == 1
    )

    # 30 entities total
    assert len(entities) == 30  # noqa: S101
    # all stix2 lib object
    assert all(  # noqa: S101
        isinstance(entity.to_stix2_object(), _STIXBase21) for entity in entities
    )
