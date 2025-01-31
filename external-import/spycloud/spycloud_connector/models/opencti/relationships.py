from datetime import datetime
from typing import Literal, Optional

import pycti
import stix2
from pydantic import Field, PrivateAttr, model_validator
from spycloud_connector.models.opencti import (
    Author,
    Incident,
    ObservableBaseModel,
    OCTIBaseModel,
    TLPMarking,
)


class BaseRelationship(OCTIBaseModel):
    """Represents a Base relationship."""

    _relationship_type: str = PrivateAttr(...)

    description: Optional[str] = Field(
        description="Description of the relationship.",
        min_length=1,
        default=None,
    )
    source: OCTIBaseModel = Field(
        description="The source entity of the relationship.",
    )
    target: OCTIBaseModel = Field(
        description="The target entity of the relationship.",
    )
    author: Author = Field(
        description="Reference to the author that reported this relationship.",
    )
    created_at: Optional[datetime] = Field(
        description="Creation timestamp of the relationship.",
        default=None,
    )
    modified_at: Optional[datetime] = Field(
        description="Last modification timestamp of the relationship.",
        default=None,
    )
    markings: list[TLPMarking] = Field(
        description="References for object marking",
    )  # optional in STIX2 spec, but required for use case

    @model_validator(mode="before")
    @classmethod
    def _validate_input_before_init(cls, data: dict) -> dict:
        """Validate the model before initialization. Automatically called by pydantic."""
        if isinstance(data, dict):
            return cls._validate_model_input(data)
        return data

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        """Validate the model input. Should be overwritten in subclasses to implement validation logic."""
        return data

    def to_stix2_object(self) -> stix2.v21.Relationship:
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type=self._relationship_type,
                source_ref=self.source.id,
                target_ref=self.target.id,
            ),
            relationship_type=self._relationship_type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            description=self.description,
            created_by_ref=self.author.id,
            created=self.created_at,
            modified=self.modified_at,
            object_marking_refs=[marking.id for marking in self.markings],
        )


class RelatedTo(BaseRelationship):
    """Represents a relationship indicating that an observable is related to an incident."""

    _relationship_type: Literal["related-to"] = "related-to"

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not isinstance(data.get("source"), ObservableBaseModel):
            raise ValueError("The source must be an Observable.")
        if not isinstance(data.get("target"), Incident):
            raise ValueError("The target must be an Incident.")
        return data
