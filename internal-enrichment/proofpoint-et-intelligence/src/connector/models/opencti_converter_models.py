from abc import abstractmethod
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

import pycti
import stix2
from connector.models.intelligence_models import FileMD5, FileSHA256
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, PrivateAttr


class OCTIConverter(BaseModel):
    """
    Base class for OpenCTI models.
    OpenCTI models are extended implementations of STIX 2.1 specification.
    All OpenCTI models implement `to_stix2_object` method to return a validated and formatted STIX 2.1 dict.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    _stix2_representation: Optional[Any] = PrivateAttr(default=None)
    _id: str = PrivateAttr(default=None)

    def model_post_init(self, context__) -> None:
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.
        Notes:
            This allows a last modification of the pydantic Model before it is eventually frozen.
        Args:
            context__(Any): The pydantic context used by pydantic framework.
        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]
        """
        self._stix2_representation = self.to_stix2_object()
        self._id = self._stix2_representation["id"]

    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        return self._id

    @property
    def stix2_representation(self) -> Optional[dict]:
        """Return the STIX 2.1 object representation of the model."""
        if self._stix2_representation is None:
            self._stix2_representation = self.to_stix2_object()
        return self._stix2_representation

    @abstractmethod
    def to_stix2_object(self) -> dict:
        """
        Abstract method to construct the corresponding STIX 2.1 object
        (usually from stix2 python lib objects)
        """


class Author(OCTIConverter):
    """Represent an author identity, typically an organization."""

    name: str = Field(..., description="Reference to the name of the author.")
    identity_class: Optional[str] = Field(
        default="organization",
        description="Reference to the identity class of the author (organization).",
    )
    description: str = Field(
        ..., description="Reference to the description of the author."
    )
    organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(None, description="Reference to Open CTI Type of the author.")

    def to_stix2_object(self) -> stix2.Identity:
        """Converted to Stix 2.1 object."""
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=self.identity_class, name=self.name
            ),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
            custom_properties={"x_opencti_organization_type": self.organization_type},
        )


class MarkingDefinition(OCTIConverter):
    """Represent a Marking definition."""

    definition_type: str = Field(
        ..., description="Reference to custom OpenCTI marking type (TLP)."
    )
    definition: str = Field(
        ...,
        description="Reference to custom OpenCTI marking definition. (TLP:AMBER+STRICT).",
    )

    def to_stix2_object(self) -> stix2.MarkingDefinition:
        """Converted to Stix 2.1 object."""
        return stix2.MarkingDefinition(
            id=pycti.MarkingDefinition.generate_id(
                self.definition_type, self.definition
            ),
            definition_type="statement",
            definition={"statement": "custom"},
            custom_properties={
                "x_opencti_definition_type": self.definition_type,
                "x_opencti_definition": self.definition,
            },
        )


class Relationship(OCTIConverter):
    """Represent a Base relationship."""

    created_by: Author = Field(
        ..., description="Reference to the author that reported this relationship."
    )
    start_time: Optional[datetime] = Field(
        default=None,
        description="This optional timestamp represents the earliest time at which the Relationship between the objects exists.",
    )
    relationship_type: str = Field(
        ..., description="Reference to the type of relationship."
    )
    source: OCTIConverter = Field(
        ..., description="Reference to the source entity of the relationship."
    )
    target: OCTIConverter = Field(
        ..., description="Reference to the target entity of the relationship."
    )
    markings: list[MarkingDefinition] = Field(
        ..., description="References for object marking."
    )

    def to_stix2_object(self) -> stix2.Relationship:
        """Converted to Stix 2.1 object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                self.relationship_type, self.source.id, self.target.id
            ),
            start_time=self.start_time,
            relationship_type=self.relationship_type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            object_marking_refs=[marking.id for marking in self.markings],
            created_by_ref=self.created_by.id,
        )


class Observable(OCTIConverter):
    """Represent observables associated with a system or an asset."""

    value: IPv4Address | str = Field(
        ..., description="Reference to the IPv4 or DomainName value."
    )
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of object marking TLP:AMBER+STRICT."
    )
    labels: Optional[list[str]] = Field(
        default=None, description="Reference to labels associated with the observable."
    )
    created_by: Author = Field(
        ..., description="Reference to the author that reported the observable."
    )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """
        Abstract method to construct the corresponding STIX 2.1 object
        (usually from stix2 python lib objects)
        """


class IPAddress(Observable):
    """Represent a ipv4 observable."""

    def to_stix2_object(self) -> stix2.IPv4Address:
        """Converted to Stix 2.1 object."""
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.created_by.id,
            },
        )


class DomainName(Observable):
    """Represent a domain name observable."""

    def to_stix2_object(self) -> stix2.DomainName:
        """Converted to Stix 2.1 object."""
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.created_by.id,
            },
        )


class File(OCTIConverter):
    """Represent a domain name observable."""

    hash_md5: FileMD5 = Field(..., description="Reference to .")
    hash_sha256: Optional[FileSHA256] = Field(
        default=None, description="Reference to ."
    )
    size: Optional[PositiveInt] = Field(default=None, description="Reference to .")
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of object marking TLP:AMBER+STRICT."
    )
    created_by: Author = Field(
        ..., description="Reference to the author that reported the observable."
    )

    def to_stix2_object(self) -> stix2.File:
        """Converted to Stix 2.1 object."""
        hashes = {
            k: v
            for k, v in {
                "MD5": self.hash_md5,
                "SHA-256": self.hash_sha256,
            }.items()
            if v is not None
        }

        return stix2.File(
            hashes=hashes,
            size=self.size,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.created_by.id,
            },
        )


class Location(OCTIConverter):
    """Represent a location"""

    country_name: str = Field(..., description="Reference to .")
    country_code: str = Field(..., description="Reference to e.")
    region: Optional[str] = Field(default=None, description="Reference to .")
    city: Optional[str] = Field(default=None, description="Reference to .")
    latitude: Optional[float] = Field(default=None, description="Reference to .")
    longitude: Optional[float] = Field(default=None, description="Reference to .")
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of object marking TLP:AMBER+STRICT."
    )
    created_by: Author = Field(
        ..., description="Reference to the author that reported the location."
    )

    def to_stix2_object(self) -> stix2.Location:
        return stix2.Location(
            id=pycti.Location.generate_id(self.country_name, "Country"),
            name=self.country_name,
            country=self.country_code,
            region=self.region,
            city=self.city,
            latitude=self.latitude,
            longitude=self.longitude,
            object_marking_refs=[marking.id for marking in self.markings],
            created_by_ref=self.created_by.id,
            custom_properties={"x_opencti_location_type": "Country"},
        )


class Asn(OCTIConverter):
    """
    asn: PositiveInt = Field(..., description="The 16 bit autonomous system number (ASN).")
    owner: str = Field(..., description="The owner of the ASN.")
    """

    name: str = Field(..., description="Reference to .")
    number: int = Field(..., description="Reference to e.")
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of object marking TLP:AMBER+STRICT."
    )
    created_by: Author = Field(
        ..., description="Reference to the author that reported the autonomous system."
    )

    def to_stix2_object(self) -> stix2.AutonomousSystem:
        return stix2.AutonomousSystem(
            name=self.name,
            number=self.number,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.created_by.id,
            },
        )
