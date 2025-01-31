from abc import abstractmethod
from typing import Optional

import pycti
import stix2
import validators
from pydantic import Field, model_validator
from spycloud_connector.models.opencti import Author, OCTIBaseModel, TLPMarking


class ObservableBaseModel(OCTIBaseModel):
    """
    Represents observables associated with a system or an asset.
    NOTA BENE: Observables do not need determinitic stix id generation. STIX python lib handles it.
    """

    author: Author = Field(
        description="The Author reporting this observable.",
    )
    markings: list[TLPMarking] = Field(
        description="References for object marking.",
        min_length=1,
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

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._Observable:
        """Make stix object."""


class Directory(ObservableBaseModel):
    """Represent a directory observable in OpenCTI."""

    path: str = Field(
        description="Specifies the path of the directory.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.Directory:
        return stix2.Directory(
            path=self.path,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class DomainName(ObservableBaseModel):
    """Represent a domain name observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the domain name.",
        min_length=1,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not validators.domain(data.get("value")):
            raise ValueError("The provided domain name is not a valid domain name.")
        return data

    def to_stix2_object(self) -> stix2.DomainName:
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class EmailAddress(ObservableBaseModel):
    """Represent an email address observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the email address. This MUST NOT include the display name.",
        min_length=1,
    )
    display_name: Optional[str] = Field(
        description="Specifies a single email display name, i.e., the name that is displayed to the human user of a mail application.",
        min_length=1,
        default=None,
    )
    belongs_to_ref: Optional[str] = Field(
        description="Specifies the user account that the email address belongs to, as a reference to a User Account object.",
        min_length=1,
        default=None,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not validators.email(data.get("value")):
            raise ValueError("The provided email address is not a valid email address.")
        return data

    def to_stix2_object(self) -> stix2.EmailAddress:
        return stix2.EmailAddress(
            value=self.value,
            display_name=self.display_name,
            belongs_to_ref=self.belongs_to_ref,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class File(ObservableBaseModel):
    """Represent a file observable in OpenCTI."""

    name: str = Field(
        description="Specifies the name of the file.",
        min_length=1,
    )  # optional in STIX2 spec, but required for use case

    def to_stix2_object(self) -> stix2.File:
        return stix2.File(
            name=self.name,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class IPv4Address(ObservableBaseModel):
    """Represent an IP address observable."""

    value: str = Field(
        description="Specifies the value of one IPv4 address.",
        min_length=1,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not validators.ipv4(data.get("value")):
            raise ValueError("The provided IP address is not a valid IPv4 address.")
        return data

    def to_stix2_object(self) -> stix2.v21.IPv4Address:
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class IPv6Address(ObservableBaseModel):
    """Represent an IP address observable."""

    value: str = Field(
        description="Specifies the value of one IPv6 address.",
        min_length=1,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not validators.ipv6(data.get("value")):
            raise ValueError("The provided IP address is not a valid IPv6 address.")
        return data

    def to_stix2_object(self) -> stix2.v21.IPv6Address:
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class MACAddress(ObservableBaseModel):
    """Represent a MAC address observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of a single MAC address.",
        min_length=1,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not validators.mac_address(data.get("value")):
            raise ValueError("The provided MAC address is not a valid MAC address.")
        return data

    def to_stix2_object(self) -> stix2.MACAddress:
        return stix2.MACAddress(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class URL(ObservableBaseModel):
    """Represent a URL observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the URL.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.URL:
        return stix2.URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class UserAccount(ObservableBaseModel):
    """Represent a user account observable."""

    account_login: Optional[str] = Field(
        description="Specifies the account login (what a user would type when they login).",
        min_length=1,
        default=None,
    )
    account_type: Optional[str] = Field(
        description="Specifies the type of the account.",
        min_length=1,
        default=None,
    )

    @classmethod
    def _validate_model_input(cls, data: dict) -> dict:
        if not data.get("account_login") and not data.get("account_type"):
            raise ValueError(
                "At least one of the fields 'account_login' or 'account_type' must be provided."
            )
        return data

    def to_stix2_object(self) -> stix2.UserAccount:
        return stix2.UserAccount(
            account_login=self.account_login,
            account_type=self.account_type,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class UserAgent(ObservableBaseModel):
    """Represent a user agent observable (custom object)."""

    value: str = Field(
        description="Specifies the value of a user agent.",
        min_length=1,
    )

    def to_stix2_object(self) -> pycti.CustomObservableUserAgent:
        return pycti.CustomObservableUserAgent(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )
