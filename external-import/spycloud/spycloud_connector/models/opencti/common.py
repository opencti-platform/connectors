from abc import abstractmethod
from typing import Literal, Optional

import pycti
import stix2
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

AuthorIdentityClass = Literal[
    "individual", "group", "system", "organization", "class", "unknown"
]
TLPMarkingLevel = Literal["white", "green", "amber", "amber+strict", "red"]


class OCTIBaseModel(BaseModel):
    """
    Base class for OpenCTI models.
    OpenCTI models are extended implementations of STIX 2.1 specification.
    All OpenCTI models implement `to_stix2_object` method to return a validated and formatted STIX 2.1 dict.
    """

    model_config: ConfigDict = ConfigDict(extra="forbid", frozen=True)

    _stix2_representation: stix2.v21._STIXBase21 = PrivateAttr(default=None)
    _id: str = PrivateAttr(default=None)

    def model_post_init(self, _):
        self._stix2_representation = self.to_stix2_object()
        self._id = self._stix2_representation["id"]

    @property
    def id(self) -> str:
        return self._id

    @property
    def stix2_representation(self) -> stix2.v21._STIXBase21:
        if self._stix2_representation is None:
            self._stix2_representation = self.to_stix2_object()
        return self._stix2_representation

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Construct STIX 2.1 object (usually from stix2 python lib objects)"""
        ...


class Author(OCTIBaseModel):  # TODO complete description
    """
    Class representing an OpenCTI author.
    Implements `to_stix2_object` that returns a STIX2 Identity object.
    """

    name: str = Field(
        description="The name of the author referring to a specific entity (e.g., an individual or organization)",
        min_length=1,
    )
    identity_class: AuthorIdentityClass = Field(
        description="The type of entity that the author describes, e.g., an individual or organization.",
    )
    description: Optional[str] = Field(
        description="A human readable description of the entity represented byt the author",
        min_length=1,
        default=None,
    )

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(self.name, self.identity_class),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
        )


class TLPMarking(OCTIBaseModel):
    """
    Represent a TLP marking definition.
    Implements `to_stix2_object` that returns a STIX2 MarkingDefinition object.
    """

    level: TLPMarkingLevel = Field(
        description="The level of the marking.",
    )

    def to_stix2_object(self) -> stix2.v21.MarkingDefinition:
        mapping = {
            "white": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[self.level]
