from datetime import datetime
from typing import Literal, Optional

import pycti
import stix2
from pydantic import Field
from spycloud_connector.models.opencti import Author, OCTIBaseModel, TLPMarking

IncidentSeverity = Literal["low", "medium", "high", "critical"]


class Incident(OCTIBaseModel):
    """
    Class representing an OpenCTI incident.
    Implements `to_stix2_ojbect` that returns a STIX2 Incident object.
    """

    name: str = Field(
        description="A name used to identify the incident.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="A description that provides more details and context about the incident, potentially including its purpose and its key characteristics.",
        min_length=1,
        default=None,
    )
    author: Author = Field(
        description="The author reporting this incident.",
    )
    created_at: datetime = Field(
        description="Represents the time at which the incident was originally reported."
    )
    updated_at: Optional[datetime] = Field(
        description="Must be set when creating a new version of an object if the created property was set.",
        default=None,
    )
    markings: list[TLPMarking] = Field(
        description="References for object markings.",
        min_length=1,
    )  # optional in STIX2 spec, but required for use case
    source: str = Field(
        description="Name of the source incident has been detected from.",
        min_length=1,
    )
    severity: IncidentSeverity = Field(
        description="Level of incident's severity",
    )
    incident_type: str = Field(
        description="A type that describes the incident.",
        min_length=1,
    )
    first_seen: datetime = Field(
        description="Represents the time at which the incident was first detected.",
    )
    last_seen: Optional[datetime] = Field(
        description="Represents the time at which the incident was last detected.",
        default=None,
    )

    def to_stix2_object(self) -> stix2.Incident:
        return stix2.Incident(
            id=pycti.Incident.generate_id(self.name, self.created_at),
            name=self.name,
            description=self.description,
            created=self.created_at,
            created_by_ref=self.author.id,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                # ! No prefix 'x_opencti' for incident's properties (not supported by OpenCTI)
                "source": self.source,
                "severity": self.severity,
                "incident_type": self.incident_type,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
            },
        )
