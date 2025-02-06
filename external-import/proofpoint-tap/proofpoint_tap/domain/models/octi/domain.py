"""Define OpenCTI entities."""

from typing import Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs

# Note: AwareDatetime, TLPMarking and ExternalReferenceneed to be imported not only if TYPE_CHECKING for pydantic to fully define Models that aggregate these fields
from proofpoint_tap.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from pydantic import AwareDatetime, Field


class KillChainPhase(BaseEntity):
    """Represent a kill chain phase."""

    chain_name: str = Field(..., description="Name of the kill chain.")
    phase_name: str = Field(..., description="Name of the kill chain phase.")

    def to_stix2_object(self) -> stix2.v21.KillChainPhase:
        """Make stix object."""
        return stix2.KillChainPhase(
            kill_chain_name=self.chain_name,
            phase_name=self.phase_name,
            # unused
            custom_properties=None,
        )


class Organization(BaseEntity):
    """Represent an organization."""

    name: str = Field(..., description="Name of the organization.", min_length=1)
    description: Optional[str] = Field(
        None, description="Description of the organization."
    )
    confidence: Optional[int] = Field(
        None, description="Organization confidence level", ge=0, le=100
    )
    author: Optional["Author"] = Field(None, description="Author of the organization.")
    labels: Optional[list[str]] = Field(None, description="Labels of the organization.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the organization."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the organization."
    )
    contact_information: Optional[str] = Field(
        None, description="Contact information for the organization."
    )
    organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(None, description="Open CTI Type of the organization.")
    reliability: Optional[str] = Field(
        None, description="Open CTI Reliability of the organization."
    )
    aliases: Optional[list[str]] = Field(
        None, description="Aliases of the organization."
    )

    def to_stix2_object(self) -> stix2.v21.Identity:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        identity_class = "organization"
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=identity_class, name=self.name
            ),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            contact_information=self.contact_information,
            confidence=self.confidence,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            created_by_ref=self.author.id if self.author else None,
            # unused
            created=None,
            modified=None,
            roles=None,
            sectors=None,
            revoked=None,
            labels=None,
            lang=None,
            # customs
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_organization_type=self.organization_type,
                x_opencti_reliability=self.reliability,
                x_opencti_aliases=self.aliases,
            ),
        )


class OrganizationAuthor(Author, Organization):
    """Represent an organization author."""

    def to_stix2_object(self) -> stix2.v21.Identity:
        """Make stix object."""
        return Organization.to_stix2_object(self)


class Campaign(BaseEntity):
    """Represent a campaign."""

    name: str = Field(..., description="Name of the campaign.", min_length=1)
    description: str = Field(..., description="Description of the campaign.")
    labels: Optional[list[str]] = Field(None, description="Labels of the campaign.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the campaign."
    )
    author: Optional["Author"] = Field(None, description="Author of the campaign.")
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the campaign."
    )
    first_seen: Optional["AwareDatetime"] = Field(
        None, description="First seen date of the campaign."
    )
    last_seen: Optional["AwareDatetime"] = Field(
        None, description="Last seen date of the campaign."
    )

    def to_stix2_object(self) -> stix2.v21.Campaign:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Campaign(
            id=pycti.Campaign.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            labels=self.labels,
            created_by_ref=self.author.id if self.author is not None else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            objective=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties={},
        )


class IntrusionSet(BaseEntity):
    """Represent an intrusion set."""

    name: str = Field(..., description="Name of the intrusion set.", min_length=1)
    description: str = Field(..., description="Description of the intrusion set.")
    labels: Optional[list[str]] = Field(
        None, description="Labels of the intrusion set."
    )
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the intrusion set."
    )
    author: Optional["Author"] = Field(None, description="Author of the intrusion set.")
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the intrusion set."
    )

    def to_stix2_object(self) -> stix2.v21.IntrusionSet:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            created_by_ref=self.author.id if self.author is not None else None,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            first_seen=None,
            last_seen=None,
            aliases=None,
            goals=None,
            resource_level=None,
            primary_motivation=None,
            secondary_motivations=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties={},
        )


class Malware(BaseEntity):
    """Represent a malware."""

    name: str = Field(..., description="Name of the malware.", min_length=1)
    types: Optional[
        list[
            Literal[
                "adware",
                "backdoor",
                "bootkit",
                "bot",
                "ddos",
                "downloader",
                "dropper",
                "exploit-kit",
                "keylogger",
                "ransomware",
                "remote-access-trojan",
                "resource-exploitation",
                "rogue-security-software",
                "rootkit",
                "screen-capture",
                "spyware",
                "trojan",
                "unknown",
                "virus",
                "webshell",
                "wiper",
                "worm",
            ]
        ]
    ] = Field(None, description="Types of the malware.")
    is_family: bool = Field(..., description="Is the malware a family?")
    description: Optional[str] = Field(None, description="Description of the malware.")
    architecture_execution_env: Optional[
        list[
            Literal[
                "alpha", "arm", "ia-64", "mips", "powerpc", "sparc", "x86", "x86-64"
            ]
        ]
    ] = Field(None, description="Architecture execution environment of the malware.")
    implementation_languages: Optional[
        list[
            Literal[
                "applescript",
                "bash",
                "c",
                "c#",
                "c++",
                "go",
                "java",
                "javascript",
                "lua",
                "objective-c",
                "perl",
                "php",
                "powershell",
                "python",
                "ruby",
                "rust",
                "scala",
                "swift",
                "typescript",
                "visual-basic",
                "x86-32",
                "x86-64",
            ]
        ]
    ] = Field(None, description="Implementation languages of the malware.")
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        None, description="Kill chain phases of the malware."
    )
    author: Optional["Author"] = Field(None, description="Author of the malware.")
    labels: Optional[list[str]] = Field(None, description="Labels of the malware.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the malware."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the malware."
    )

    def to_stix2_object(self) -> stix2.v21.Malware:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Malware(
            id=pycti.Malware.generate_id(name=self.name),
            created_by_ref=self.author.id if self.author is not None else None,
            name=self.name,
            description=self.description,
            malware_types=self.types,
            is_family=self.is_family,
            architecture_execution_envs=self.architecture_execution_env,
            implementation_languages=self.implementation_languages,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            first_seen=None,
            last_seen=None,
            operating_system_refs=None,
            capabilities=None,
            sample_refs=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties={},
        )


class AttackPattern(BaseEntity):
    """Represent an attack pattern."""

    name: str = Field(..., description="Name of the attack pattern.", min_length=1)
    external_id: Optional[str] = Field(
        None, description="External ID of the attack pattern."
    )
    description: Optional[str] = Field(
        None, description="Description of the attack pattern."
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        None, description="Kill chain phases of the attack pattern."
    )
    author: Optional["Author"] = Field(
        None, description="Author of the attack pattern."
    )
    labels: Optional[list[str]] = Field(
        None, description="Labels of the attack pattern."
    )
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the attack pattern."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the attack pattern."
    )

    def to_stix2_object(self) -> stix2.v21.AttackPattern:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(name=self.name),
            created_by_ref=self.author.id if self.author is not None else None,
            name=self.name,
            description=self.description,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            aliases=None,
            created=None,
            modified=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties={
                # "x_opencti_score": self.risk_score or None,
                # "x_opencti_labels": self.labels,
                # "x_opencti_external_references": self.external_references,
                # "x_mitre_id": self.mitre_id,
            },
        )


class TargetedOrganization(Organization):
    """Represent a targeted organization."""


class Report(BaseEntity):
    """Represent a report."""

    name: str = Field(..., description="Name of the report.", min_length=1)
    publication_date: "AwareDatetime" = Field(
        ..., description="Publication date of the report."
    )
    report_status: Literal["New", "In progress", "Analyzed", "Closed"] = Field(
        ..., description="Status of the report."
    )
    report_types: Optional[
        list[
            Literal[
                "breach_alert",
                "fintel",
                "inforep",
                "intelligence_summary",
                "internal-report",
                "malware",
                "spotrep",
                "threat-report",
            ]
        ]
    ] = Field(None, description="Report types.")
    reliabilty: Optional[
        Literal[
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
        ]
    ] = Field(None, description="Reliability of the report.")
    description: Optional[str] = Field(None, description="Description of the report.")
    content: Optional[str] = Field(None, description="Content of the report.")
    # confidence no set via code anymore
    # assignees not set via code
    # participants not set by code

    author: Optional["Author"] = Field(None, description="Author of the report.")
    labels: Optional[list[str]] = Field(None, description="Labels of the report.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the report."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the report."
    )
    objects: list[BaseEntity] = Field(
        ..., description="Objects of the report.", min_length=1
    )

    def to_stix2_object(self) -> stix2.v21.Report:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        reliability_mapping = {
            "A": "A - Completely reliable",
            "B": "B - Usually reliable",
            "C": "C - Fairly reliable",
            "D": "D - Not usually reliable",
            "E": "E - Unreliable",
            "F": "F - Reliability cannot be judged",
        }

        return stix2.Report(
            id=pycti.Report.generate_id(
                name=self.name, published=self.publication_date
            ),
            created_by_ref=self.author.id if self.author is not None else None,
            name=self.name,
            description=self.description,
            object_refs=[obj.id for obj in self.objects],
            report_types=self.report_types,
            published=self.publication_date,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            labels=self.labels,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # custom
            custom_properties={
                "x_opencti_reliability": (
                    reliability_mapping.get(self.reliabilty)
                    if self.reliabilty
                    else None
                ),
                "x_opencti_report_status": self.report_status,
            },
            # unused
            created=None,
            modified=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class Incident(BaseEntity):
    """Represent an incident."""

    name: str = Field(..., description="Name of the incident.", min_length=1)
    incident_type: Optional[
        Literal[
            "alert",
            "compromise",
            "cybercrime",
            "data-leak",
            "information-system-disruption",
            "phishing",
            "ransomware",
            "reputation-damage",
            "typosquatting",
        ]
    ] = Field(None, description="Type of the incident.")
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Field(
        None, description="Severity of the incident.", ge=0, le=10
    )
    description: Optional[str] = Field(None, description="Description of the incident.")
    source: Optional[str] = Field(None, description="Source of the incident.")
    # assignees: Optional[list[str]] = Field(None, description="Assignee(s) of the incident.")
    # participants: Optional[list[str]] = Field(None, description="Participants of the incident.")
    author: Optional["Author"] = Field(
        None, description="Author reporting the incident."
    )
    labels: Optional[list[str]] = Field(None, description="Labels of the incident.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the incident."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the incident."
    )
    first_seen: Optional["AwareDatetime"] = Field(
        None, description="First seen date of the incident."
    )
    last_seen: Optional["AwareDatetime"] = Field(
        None, description="Last seen date of the incident."
    )
    objective: Optional[str] = Field(None, description="Objective.")

    def to_stix2_object(self) -> stix2.v21.Incident:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Incident(
            id=pycti.Incident.generate_id(name=self.name, created=self.first_seen),
            name=self.name,
            description=self.description,
            created_by_ref=self.author.id if self.author is not None else None,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            kill_chain_phases=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties={
                "source": self.source,
                "severity": self.severity,
                "incident_type": self.incident_type,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
            },
        )
