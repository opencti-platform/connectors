from pydantic import BaseModel, Field, PrivateAttr, ConfigDict
from abc import abstractmethod
from typing import Any, Literal
from datetime import datetime
import stix2
import pycti


class OCTIBaseModel(BaseModel):
    """
    Base class for OpenCTI models.
    """

    model_config: ConfigDict = ConfigDict(extra="forbid", frozen=True)

    _stix2_representation = PrivateAttr(default=None)
    _id = PrivateAttr(default=None)

    def model_post_init(self):
        self._stix2_representation = self.to_stix2_object()
        self._id = self._stix2_representation["id"]

    @property
    def id(self):
        return self._id

    @property
    def stix2_representation(self):
        if self._stix2_representation is None:
            self._stix2_representation = self.to_stix2_object()
        return self._stix2_representation

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct STIX 2.1 object (usually from stix2 python lib objects)"""
        ...


class Author(OCTIBaseModel):  # TODO complete description
    """
    Class for OpenCTI authors.
    """

    name: str = Field(description="", min_length=1)
    description: str = Field(description="", min_length=1)
    identity_class: Literal["organization"] = Field(
        description="", default="organization"
    )
    object_marking_refs: list[stix2.MarkingDefinition] = Field(
        description="", default=[]
    )

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(self.name, self.identity_class),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
            object_marking_refs=self.object_marking_refs,
        )


class Incident(OCTIBaseModel):  # TODO: complete description
    """
    Class for OpenCTI incidents.
    """

    name: str = Field(description="", min_length=1)
    description: str = Field(description="", min_length=1)
    source: str = Field(description="", min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = Field(description="")
    author: Author = Field(description="")
    created_at: datetime = Field(description="")
    updated_at: datetime = Field(description="")
    object_marking_refs: list[stix2.MarkingDefinition] = Field(
        description="", default=[]
    )
    external_references: list[dict] = Field(description="", default=[])

    def to_stix2_object(self) -> stix2.Incident:
        return stix2.Incident(
            id=pycti.Incident.generate_id(self.name, self.created_at),
            name=self.name,
            description=self.description,
            created=self.created_at,
            created_by_ref=self.author.id,
            object_marking_refs=self.object_marking_refs,
            external_references=self.external_references,
            custom_properties={
                "source": self.source,
                "severity": self.severity,
                "incident_type": "data-breach",
                "first_seen": self.created_at,
                "last_seen": self.updated_at,
            },
        )
