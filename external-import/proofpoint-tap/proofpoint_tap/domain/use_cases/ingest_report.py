"""Offer tools to ingest Report and related entities from TAP Campaigns."""

from itertools import product
from typing import TYPE_CHECKING, Any, Generator, Iterable, Optional

from proofpoint_tap.domain.models.octi.domain import (
    AttackPattern,
    IntrusionSet,
    Malware,
    Report,
    TargetedOrganization,
)
from proofpoint_tap.domain.models.octi.observables import Url
from proofpoint_tap.domain.models.octi.relationships import (
    IndicatorBasedOnObservable,
    IndicatorIndicatesIntrusionSet,
    IndicatorIndicatesMalware,
    IntrusionSetTargetsOrganization,
    IntrusionSetUsesAttackPattern,
    IntrusionSetUsesMalware,
)
from proofpoint_tap.domain.use_cases.common import BaseUseCase

if TYPE_CHECKING:
    from proofpoint_tap.domain.models.octi import BaseEntity
    from proofpoint_tap.domain.models.octi.observables import Indicator, Observable
    from proofpoint_tap.ports.campaign import CampaignPort, ObservedDataPort


class ReportProcessor(BaseUseCase):
    """Process simply the data from a ProofPoint Campaign.

    Examples:
        >>> from proofpoint_tap.ports.campaign import CampaignPort, ObservedDataPort
        >>> from proofpoint_tap.domain.models.octi import TLPMarking
        >>> from datetime import datetime, timezone
        >>> class DummyObservedData(ObservedDataPort):
        ...     def __init__(self, type_: str, value: str, observed_at: datetime):
        ...         self._type = type_
        ...         self._value = value
        ...         self._observed_at = observed_at
        ...     @property
        ...     def type_(self) -> str:
        ...         return self._type
        ...     @property
        ...     def value(self) -> str:
        ...         return self._value
        ...     @property
        ...     def observed_at(self) -> "datetime":
        ...         return self._observed_at
        >>> class DummyCampaign(CampaignPort):
        ...     def __init__(self, name: str, start_datetime: datetime, description: str, actor_names: list[str], malware_names: list[str], technique_names: list[str], observed_data: list[DummyObservedData], targeted_brand_names: list[str]):
        ...         self._name = name
        ...         self._start_datetime = start_datetime
        ...         self._description = description
        ...         self._actor_names = actor_names
        ...         self._malware_names = malware_names
        ...         self._technique_names = technique_names
        ...         self._targeted_brand_names = targeted_brand_names
        ...         self._observed_data = observed_data
        ...     @property
        ...     def name(self) -> str:
        ...         return self._name
        ...     @property
        ...     def start_datetime(self) -> "datetime":
        ...         return self._start_datetime
        ...     @property
        ...     def description(self) -> str:
        ...         return self._description
        ...     @property
        ...     def actor_names(self) -> list[str]:
        ...         return self._actor_names
        ...     @property
        ...     def malware_names(self) -> list[str]:
        ...         return self._malware_names
        ...     @property
        ...     def malware_family_names(self) -> list[str]:
        ...         return self._malware_names
        ...     @property
        ...     def technique_names(self) -> list[str]:
        ...         return self._technique_names
        ...     @property
        ...     def targeted_brand_names(self) -> list[str]:
        ...         return self._targeted_brand_names
        ...     @property
        ...     def observed_data(self) -> list[DummyObservedData]:
        ...         return self._observed_data
        >>> campaign = DummyCampaign(
        ...     name="Campaign 1",
        ...     start_datetime=datetime.now(timezone.utc),
        ...     description="Campaign description",
        ...     actor_names=["actor1", "actor2"],
        ...     malware_names=["malware1", "malware2"],
        ...     technique_names=["technique1", "technique2"],
        ...     observed_data=[
        ...         DummyObservedData(type_="url", value="http://example.com", observed_at=datetime.now(timezone.utc)),
        ...         DummyObservedData(type_="ip", value="127.0.0.1", observed_at=datetime.now(timezone.utc))
        ...     ],
        ...     targeted_brand_names=["brand1", "brand2"]
        ... )
        >>> processor = ReportProcessor(tlp_marking=TLPMarking(level="white"))
        >>> entities = processor.run_on(campaign)


    """

    def make_intrusion_sets(
        self, campaign: "CampaignPort"
    ) -> Generator[IntrusionSet, Any, Any]:
        """Make an OCTI IntrusionSet generation from a ProofPoint TAP campaign."""

        def make_intrusion_set(actor_name: str) -> IntrusionSet:
            """Make an OCTI IntrusionSet from a ProofPoint TAP actor name."""
            return IntrusionSet(
                name=actor_name,
                description="",
                labels=None,
                markings=[self.tlp_marking],
                author=self.author,
                external_references=None,
            )

        for actor in campaign.actor_names:
            yield make_intrusion_set(actor)

    def make_attach_patterns(
        self, campaign: "CampaignPort"
    ) -> Generator[AttackPattern, Any, Any]:
        """Make an OCTI Attack Pattern generator from a ProofPoint TAP campaign."""

        def make_attack_pattern(tap_technique_name: str) -> AttackPattern:
            """Make an OCTI AttackPattern from a ProofPoint TAP technique name.

            Args:
                tap_technique_name (str): The technique to ingest.
                tlp_marking (TLPMarking): default marking for ingested objects.

            """
            return AttackPattern(
                name=tap_technique_name,
                external_id=None,
                description=None,
                kill_chain_phases=None,
                author=self.author,
                labels=None,
                markings=[self.tlp_marking],
                external_references=None,
            )

        for technique in campaign.technique_names:
            yield make_attack_pattern(technique)

    def make_malwares(self, campaign: "CampaignPort") -> Generator[Malware, Any, Any]:
        """Make an OCTI Malware generator from a ProofPoint TAP campaign."""

        def make_malware(tap_malware_name: str) -> Malware:
            """Make an OCTI Malware from a ProofPoint TAP malware name.

            Args:
                tap_malware_name (str): The malware to ingest.
                tlp_marking (TLPMarking): default marking for ingested objects.

            """
            return Malware(
                name=tap_malware_name,
                description=None,
                labels=None,
                markings=[self.tlp_marking],
                author=self.author,
                external_references=None,
                is_family=False,
                # unused
                types=None,
                architecture_execution_env=None,
                implementation_languages=None,
                kill_chain_phases=None,
            )

        for malware in campaign.malware_names:
            yield make_malware(malware)

    def make_observables_and_indicators(
        self, campaign: "CampaignPort"
    ) -> Generator[tuple["Observable", "Indicator"], Any, Any]:
        """Make an OCTI Observable and Indicator generator from a ProofPoint TAP campaign."""

        def make_observable_and_indicator(
            observed_data: "ObservedDataPort",
        ) -> Optional[tuple["Observable", "Indicator"]]:
            """Make an OCTI Observable and Indicator from a proofpoint TAP  campaign observed data."""
            if observed_data.type_ == "url":
                observable = Url(
                    value=observed_data.value,
                    description=None,
                    labels=None,
                    external_references=None,
                    markings=[self.tlp_marking],
                    author=self.author,
                    # unused
                    score=None,
                )
                indicator = observable.to_indicator(
                    valid_from=observed_data.observed_at
                )
            else:
                return None
            return observable, indicator

        for observed_data in campaign.observed_data:
            observable_and_indicator = make_observable_and_indicator(observed_data)
            if observable_and_indicator is not None:
                yield observable_and_indicator

    def make_targeted_organizations(
        self, campaign: "CampaignPort"
    ) -> Generator[TargetedOrganization, Any, Any]:
        """Make an OCTI TargetedOrganization generator from a ProofPoint TAP campaign."""

        def make_targeted_organization(tap_brand_name: str) -> TargetedOrganization:
            """Make an OCTI TargetedOrganization from a ProofPoint TAP brand.

            Args:
                tap_brand_name (str): The brand to ingest.

            """
            return TargetedOrganization(
                name=tap_brand_name,
                description=None,
                labels=None,
                markings=[self.tlp_marking],
                author=self.author,
                contact_information=None,
                organization_type=None,
                external_references=None,
                confidence=None,
                reliability=None,
                aliases=None,
            )

        for brand_name in campaign.targeted_brand_names:
            yield make_targeted_organization(brand_name)

    def make_instrusion_sets_targets_organizations_relationship(
        self,
        intrusion_sets: Iterable[IntrusionSet],
        targeted_organizations: Iterable[TargetedOrganization],
    ) -> Generator[IntrusionSetTargetsOrganization, Any, Any]:
        """Make an OCTI IntrusionSetTargetsOrganizations relationship from IntrusionSet and TargetedOrganization."""
        for intrusion_set, targeted_organization in product(
            list(intrusion_sets), list(targeted_organizations)
        ):
            yield IntrusionSetTargetsOrganization(
                author=self.author,
                source=intrusion_set,
                target=targeted_organization,
                markings=[self.tlp_marking],
                # unused
                created=None,
                modified=None,
                description=None,
                start_time=None,
                stop_time=None,
                confidence=None,
                external_references=None,
            )

    def make_intrusion_set_uses_malwares_relationship(
        self, intrusion_sets: Iterable[IntrusionSet], malwares: Iterable[Malware]
    ) -> Generator[IntrusionSetUsesMalware, Any, Any]:
        """Make an OCTI IntrusionSetUsesMalware relationship from IntrusionSet and Malware."""
        for intrusion_set, malware in product(intrusion_sets, malwares):
            yield IntrusionSetUsesMalware(
                author=self.author,
                source=intrusion_set,
                target=malware,
                markings=[self.tlp_marking],
                # unused
                created=None,
                modified=None,
                description=None,
                start_time=None,
                stop_time=None,
                confidence=None,
                external_references=None,
            )

    def make_intrusion_set_uses_attack_patterns_relationship(
        self,
        intrusion_sets: Iterable[IntrusionSet],
        attack_patterns: Iterable[AttackPattern],
    ) -> Generator[IntrusionSetUsesAttackPattern, Any, Any]:
        """Make an OCTI IntrusionSetUsesAttackPattern relationship from IntrusionSet and AttackPattern."""
        for intrusion_set, attack_pattern in product(intrusion_sets, attack_patterns):
            yield IntrusionSetUsesAttackPattern(
                author=self.author,
                source=intrusion_set,
                target=attack_pattern,
                markings=[self.tlp_marking],
                # unused
                created=None,
                modified=None,
                description=None,
                start_time=None,
                stop_time=None,
                confidence=None,
                external_references=None,
            )

    def make_indicators_indicates_malwares_relationship(
        self, indicators: Iterable["Indicator"], malwares: Iterable[Malware]
    ) -> Generator[IndicatorIndicatesMalware, Any, Any]:
        """Make an OCTI IndicatorIndicatesMalware relationship from Indicator and Malware."""
        for indicator, malware in product(indicators, malwares):
            yield IndicatorIndicatesMalware(
                author=self.author,
                source=indicator,
                target=malware,
                markings=[self.tlp_marking],
                # unused
                created=None,
                modified=None,
                description=None,
                start_time=None,
                stop_time=None,
                confidence=None,
                external_references=None,
            )

    def make_indicators_indicates_intrusion_sets_relationship(
        self, indicators: Iterable["Indicator"], intrusion_sets: Iterable[IntrusionSet]
    ) -> Generator[IndicatorIndicatesIntrusionSet, Any, Any]:
        """Make an OCTI IndicatorIndicatesIntrusionSet relationship from Indicator and IntrusionSet."""
        for indicator, intrusion_set in product(indicators, intrusion_sets):
            yield IndicatorIndicatesIntrusionSet(
                author=self.author,
                source=indicator,
                target=intrusion_set,
                markings=[self.tlp_marking],
                # unused
                created=None,
                modified=None,
                description=None,
                start_time=None,
                stop_time=None,
                confidence=None,
                external_references=None,
            )

    def make_indicator_indicates_observable_relationship(
        self, indicator: "Indicator", observable: "Observable"
    ) -> IndicatorBasedOnObservable:
        """Make an OCTI IndicatorBasedOnObservable relationship from Indicator and Observable."""
        return IndicatorBasedOnObservable(
            author=self.author,
            source=indicator,
            target=observable,
            markings=[self.tlp_marking],
            # unused
            created=None,
            modified=None,
            description=None,
            start_time=None,
            stop_time=None,
            confidence=None,
            external_references=None,
        )

    def make_report(
        self, campaign: "CampaignPort", related_objetcs: list["BaseEntity"]
    ) -> Report:
        """Make an OCTI Report from a ProofPoint TAP campaign and the related entities."""
        return Report(
            name=campaign.name,
            publication_date=campaign.start_datetime,
            description=campaign.description,
            labels=campaign.malware_family_names,
            markings=[self.tlp_marking],
            author=self.author,
            external_references=None,
            objects=related_objetcs,
            report_status="New",
            # unused
            report_types=None,
            reliabilty=None,
            content=None,
        )

    def run_on(self, tap_campaign: "CampaignPort") -> list["BaseEntity"]:
        """Run the process of entities creation thanks to a TAP Campaign."""
        entities: list["BaseEntity"] = []  # result holder

        # Process associated actors
        intrusion_sets = list(self.make_intrusion_sets(tap_campaign))

        # Process associated malware
        malwares = list(self.make_malwares(tap_campaign))

        # Process associated techniques
        attack_patterns = list(self.make_attach_patterns(tap_campaign))

        # Process associated brands
        targeted_organizations = list(self.make_targeted_organizations(tap_campaign))

        # process observed data
        o_i = list(self.make_observables_and_indicators(tap_campaign))
        observables, indicators = zip(*o_i, strict=True) if o_i else ((), ())

        # add to entities
        entities.extend(intrusion_sets)
        entities.extend(malwares)
        entities.extend(attack_patterns)
        entities.extend(targeted_organizations)
        entities.extend(observables)
        entities.extend(indicators)

        # create relationships
        ## combination of intrusion_sets and targeted_organizations
        entities.extend(  # Note: directly extending to entity list because no
            self.make_instrusion_sets_targets_organizations_relationship(
                intrusion_sets=intrusion_sets,
                targeted_organizations=targeted_organizations,
            )
        )
        ## combination of intrusion_sets and malwares
        entities.extend(
            self.make_intrusion_set_uses_malwares_relationship(
                intrusion_sets=intrusion_sets,
                malwares=malwares,
            )
        )
        ## combination of intrusion_sets and attack_patterns
        entities.extend(
            self.make_intrusion_set_uses_attack_patterns_relationship(
                intrusion_sets=intrusion_sets,
                attack_patterns=attack_patterns,
            )
        )
        ## combination of indicators and malwares
        entities.extend(
            self.make_indicators_indicates_malwares_relationship(
                indicators=indicators,
                malwares=malwares,
            )
        )
        ## combination of indicators and intrusion_sets
        entities.extend(
            self.make_indicators_indicates_intrusion_sets_relationship(
                indicators=indicators,
                intrusion_sets=intrusion_sets,
            )
        )

        ## pairs of Indicators and Observables
        entities.extend(
            [
                self.make_indicator_indicates_observable_relationship(
                    indicator=indicator,
                    observable=observable,
                )
                for observable, indicator in (o_i if o_i else [])
            ]
        )

        # Only append Report and Author if at least one entity is present
        # This will avoid application to try to
        # fail if no objects in reports
        # send data with only the author.
        if entities:
            entities.append(self.make_report(tap_campaign, entities))
            entities.append(self.author)
            entities.append(self.tlp_marking)

        return entities
