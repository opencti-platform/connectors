"""Define the OpenCTI Relationships."""

from datetime import datetime
from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs

# Note: We need to import the models (even if used for typing purpose) for pydantic to work.
# Else we get a pydantic.errors.PydanticUserError: `Model` is not fully defined.
from proofpoint_tap.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from proofpoint_tap.domain.models.octi.domain import (
    AttackPattern,
    Campaign,
    Incident,
    IntrusionSet,
    Malware,
    TargetedOrganization,
)
from proofpoint_tap.domain.models.octi.observables import (
    EmailAddress,
    EmailMessage,
    Indicator,
    Observable,
)
from pydantic import Field, PrivateAttr


class BaseRelationship(BaseEntity):
    """Represent a Base relationship."""

    author: "Author" = Field(
        ..., description="Reference to the author that reported this relationship."
    )
    created: Optional["datetime"] = Field(
        None, description="Creation timestamp of the relationship."
    )
    modified: Optional["datetime"] = Field(
        None, description="Last modification timestamp of the relationship."
    )
    description: Optional[str] = Field(
        None, description="Description of the relationship."
    )
    source: BaseEntity = Field(
        ..., description="The source entity of the relationship."
    )
    target: BaseEntity = Field(
        ..., description="The target entity of the relationship."
    )
    start_time: Optional["datetime"] = Field(
        None, description="Start time of the relationship in ISO 8601 format."
    )
    stop_time: Optional["datetime"] = Field(
        None, description="End time of the relationship in ISO 8601 format."
    )
    confidence: Optional[int] = Field(
        None, description="Confidence level regarding the relationship.", ge=0, le=100
    )
    markings: Optional[list["TLPMarking"]] = Field(
        None,
        description="References for object marking",
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None,
        description="External references",
    )

    _relationship_type: str = PrivateAttr("")

    def to_stix2_object(self) -> stix2.v21.Relationship:
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type=self._relationship_type,
                source_ref=self.source.id,
                target_ref=self.target.id,
                start_time=self.start_time,
                stop_time=self.stop_time,
            ),
            relationship_type=self._relationship_type,
            **self._common_stix2_args(),
        )

    def _common_stix2_args(self) -> dict[str, Any]:
        # keep dict constructor rather than literal dict for maintainance.
        return dict(  # noqa: C408
            source_ref=self.source.id,
            target_ref=self.target.id,
            # optional
            created_by_ref=self.author.id,
            created=self.created,
            modified=self.modified,
            description=self.description,
            start_time=self.start_time,
            stop_time=self.stop_time,
            confidence=self.confidence,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=(
                [ref.to_stix2_object() for ref in self.external_references or []]
            ),
        )


class CampaignAttributedToIntrusionSet(BaseRelationship):
    """Represent a relationship indicating that a campaign is attributed to an intrusion-set.

    Examples:
        >>> campaign = Campaign(name="Campaign 1", description="Campaign description")
        >>> intrusion_set = IntrusionSet(name="Intrusion Set 1", description="Intrusion Set description")
        >>> relationship = CampaignAttributedToIntrusionSet(
        ...     author=OrganizationAuthor(name="author"),
        ...     source=campaign,
        ...     target=intrusion_set,
        ...     start_time=datetime.now(),
        ... )

    """

    # Override BaseRelationship
    source: "Campaign" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here a Campaign.",
    )
    target: "IntrusionSet" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an IntrusionSet.",
    )
    _relationship_type: Literal["attributed-to"] = "attributed-to"


class CampaignUsesMalware(BaseRelationship):
    """Represent a relationship indicating that a campaign uses a malware."""

    # Override BaseRelationship
    source: "Campaign" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here a Campaign.",
    )
    target: "Malware" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a Malware.",
    )
    _relationship_type: Literal["uses"] = "uses"


class CampaignUsesAttackPattern(BaseRelationship):
    """Represent a relationship indicating that a campaign uses an attack pattern."""

    # Override BaseRelationship
    source: "Campaign" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here a Campaign.",
    )
    target: "AttackPattern" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an AttackPattern.",
    )
    _relationship_type: Literal["uses"] = "uses"


class CampaignTargetsOrganization(BaseRelationship):
    """Represent a relationship indicating that a campaign targets an organization."""

    # Override BaseRelationship
    source: "Campaign" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here a Campaign.",
    )
    target: "TargetedOrganization" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a TargetedOrganization.",
    )
    _relationship_type: Literal["targets"] = "targets"


class IntrusionSetTargetsOrganization(BaseRelationship):
    """Represent a relationship indicating that an intrusion set targets organization."""

    # Override BaseRelationship
    source: "IntrusionSet" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an IntrusionSet.",
    )
    target: "TargetedOrganization" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a TargetedOrganization.",
    )
    _relationship_type: Literal["targets"] = "targets"


class IntrusionSetUsesMalware(BaseRelationship):
    """Represent a relationship indicating that an intrusion set uses a malware."""

    # Override BaseRelationship
    source: "IntrusionSet" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an IntrusionSet.",
    )
    target: "Malware" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a Malware.",
    )
    _relationship_type: Literal["uses"] = "uses"


class IntrusionSetUsesAttackPattern(BaseRelationship):
    """Represent a relationship indicating that an intrusion set uses an attack pattern."""

    # Override BaseRelationship
    source: "IntrusionSet" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an IntrusionSet.",
    )
    target: "AttackPattern" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an AttackPattern.",
    )
    _relationship_type: Literal["uses"] = "uses"


class IndicatorIndicatesMalware(BaseRelationship):
    """Represent a relationship indicating that an indicator indicates a malware."""

    # Override BaseRelationship
    source: "Indicator" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: "Malware" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here a Malware.",
    )
    _relationship_type: Literal["indicates"] = "indicates"


class IndicatorIndicatesIntrusionSet(BaseRelationship):
    """Represent a relationship indicating that an indicator indicates an intrusion set."""

    # Override BaseRelationship
    source: "Indicator" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: "IntrusionSet" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an IntrusionSet.",
    )
    _relationship_type: Literal["indicates"] = "indicates"


class IndicatorBasedOnObservable(BaseRelationship):
    """Represent a relationship indicating that an indicator is based on an observable."""

    source: "Indicator" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: "Observable" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an Indicator.",
    )
    _relationship_type: Literal["based-on"] = "based-on"


class EmailAddressRelatedToIncident(BaseRelationship):
    """Represent a relationship indicating that an email address is related to incidents."""

    source: "EmailAddress" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an EmailAddress.",
    )
    target: "Incident" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an Incident.",
    )
    _relationship_type: Literal["related-to"] = "related-to"


class EmailMessageRelatedToIncident(BaseRelationship):
    """Represent a relationship indicating that an email message is related to incidents."""

    source: "EmailMessage" = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an EmailMessage.",
    )
    target: "Incident" = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an Incident.",
    )
    _relationship_type: Literal["related-to"] = "related-to"
