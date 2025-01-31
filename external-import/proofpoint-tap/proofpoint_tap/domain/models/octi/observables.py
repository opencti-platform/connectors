"""Define the OpenCTI Observable."""

from abc import abstractmethod
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs

# Note : we need to import Author, ExternalReference, TLPMarking and KillChainPhase not only if TYPE_CHECKING because pydantic needs them to fully define the models that aggregate these field types.
from proofpoint_tap.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from proofpoint_tap.domain.models.octi.domain import KillChainPhase
from pydantic import EmailStr, Field, field_validator


class Observable(BaseEntity):
    """Represents observables associated with a system or an asset.

    NOTA BENE: Observables do not need determinitic stix id generation. STIX python lib handles it.
    """

    score: Optional[int] = Field(
        None, description="Score of the observable.", ge=0, le=100
    )
    description: Optional[str] = Field(
        None, description="Description of the observable."
    )
    labels: Optional[list[str]] = Field(None, description="Labels of the observable.")
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the observable."
    )
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="References for object marking."
    )
    author: Optional["Author"] = Field(
        description="The Author reporting this Observable."
    )

    def custom_properties_to_stix(self) -> dict[str, Any]:
        """Factorize custom params."""
        return dict(  # noqa: C408 # No literal dict for maintainability
            x_opencti_score=self.score,
            x_opencti_description=self.description,
            x_opencti_labels=self.labels,
            x_opencti_external_references=[
                external_ref.to_stix2_object()
                for external_ref in (self.external_references or [])
            ],
            x_opencti_created_by_ref=self.author.id if self.author else None,
        )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Make stix object."""

    @abstractmethod
    def to_indicator(self, valid_from: Optional["datetime"] = None) -> stix2.Indicator:
        """Make indicator stix object."""


class Indicator(BaseEntity):
    """Represent an Indicator."""

    name: str = Field(..., description="Name of the indicator.", min_length=1)
    description: Optional[str] = Field(
        None, description="Description of the indicator."
    )
    indicator_types: Optional[
        list[
            Literal[
                "anomalous-activity",
                "anonymization",
                "benign",
                "compromised",
                "malicious-activity",
                "attribution",
                "unknown",
            ]
        ]
    ] = Field(None, description="Indicator types.")
    pattern_type: Literal[
        "stix",
        "eql",
        "pcre",
        "shodan",
        "sigma",
        "snort",
        "spl",
        "suricata",
        "tanium-signal",
        "yara",
    ] = Field(..., description="Pattern type.")
    pattern: str = Field(
        ...,
        description="Pattern. See Stix2.1 for instance : https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf",
    )
    platforms: Optional[list[Literal["windows", "macos", "linux", "android"]]] = Field(
        None, description="Platforms."
    )
    valid_from: Optional["datetime"] = Field(None, description="Valid from.")
    valid_until: Optional["datetime"] = Field(None, description="Valid until.")
    kill_chain_phases: Optional[list["KillChainPhase"]] = Field(
        None, description="Kill chain phases."
    )
    author: Optional["Author"] = Field(None, description="Author of the indicator.")
    markings: Optional[list["TLPMarking"]] = Field(
        None, description="Markings of the indicator."
    )
    external_references: Optional[list["ExternalReference"]] = Field(
        None, description="External references of the indicator."
    )
    observable_type: Optional[str] = Field(None, description="Observable type.")
    score: Optional[int] = Field(
        None, description="Score of the indicator.", ge=0, le=100
    )

    def to_stix2_object(self) -> stix2.v21.Indicator:
        """Make stix object."""
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern=self.pattern),
            name=self.name,
            description=self.description,
            indicator_types=self.indicator_types,
            pattern_type=self.pattern_type,
            pattern=self.pattern,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            # Unused
            created=None,
            modified=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            pattern_version=None,
            extensions=None,
            # Customs
            custom_properties=dict(  # noqa: C408 # No literal dict for maintainability
                x_opencti_score=self.score,
                x_opencti_main_observable_type=self.observable_type,
            ),
        )


class Software(Observable):
    """Represents a software observable."""

    name: str = Field(..., description="Name of the software.", min_length=1)
    version: Optional[str] = Field(None, description="Version of the software.")
    vendor: Optional[str] = Field(None, description="Vendor of the software.")
    swid: Optional[str] = Field(None, description="SWID of the software.")
    cpe: Optional[str] = Field(None, description="CPE of the software.")
    languages: Optional[list[str]] = Field(
        None, description="Languages of the software."
    )

    def to_stix2_object(self) -> stix2.v21.Software:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Software(
            name=self.name,
            version=self.version,
            vendor=self.vendor,
            swid=self.swid,
            cpe=self.cpe,
            languages=self.languages,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            granular_markings=None,
            defanged=None,
            extensions=None,
            # customs
            custom_properties=self.custom_properties_to_stix(),
        )

    def to_indicator(
        self,
        valid_from: Optional["datetime"] = None,
    ) -> Indicator:
        """Make indicator stix object."""
        stix_pattern = "AND ".join(
            [
                f"software:name = '{self.name}'",
                f"software:version = '{self.version}'" if self.version else "",
                f"software:vendor = '{self.vendor}'" if self.vendor else "",
                f"software:swid = '{self.swid}'" if self.swid else "",
                f"software:cpe = '{self.cpe}'" if self.cpe else "",
            ]
        )
        return Indicator(
            name=self.name,
            description=None,
            indicator_types=None,
            pattern_type="stix",
            pattern=stix_pattern,
            platforms=None,
            valid_from=valid_from,
            valid_until=None,
            kill_chain_phases=None,
            author=self.author,
            markings=self.markings,
            external_references=None,
            observable_type="software",
            score=self.score,
        )


class Url(Observable):
    """Represent a URL observable."""

    value: str = Field(..., description="The URL value.", min_length=1)

    def to_stix2_object(self) -> stix2.v21.URL:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            granular_markings=None,
            defanged=None,
            extensions=None,
            # customs
            custom_properties=self.custom_properties_to_stix(),
        )

    def to_indicator(
        self,
        valid_from: Optional["datetime"] = None,
    ) -> Indicator:
        """Make indicator stix object."""
        stix_pattern = f"[url:value = '{self.value}']"
        return Indicator(
            name=self.value,
            description=self.description,
            indicator_types=None,
            pattern_type="stix",
            pattern=stix_pattern,
            platforms=None,
            valid_from=valid_from,
            valid_until=None,
            kill_chain_phases=None,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
            observable_type="Url",
            score=self.score,
        )


class IPV4Address(Observable):
    """Represent an IP address observable."""

    value: str = Field(..., description="The IP address value.", min_length=1)

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value: str) -> str:
        """Validate the value of the IP V4 address."""
        try:
            IPv4Address(value)
        except ValueError:
            raise ValueError(f"Invalid IP V4 address {value}") from None
        return value

    def to_stix2_object(self) -> stix2.v21.IPv4Address:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            resolves_to_refs=None,  # This has to be an explicit resolves to mac address relationships
            belongs_to_refs=None,  # This has to be an explicit belongs to autonomous system relationship
            granular_markings=None,
            defanged=None,
            extensions=None,
            # customs
            custom_properties=self.custom_properties_to_stix(),
        )

    def to_indicator(
        self,
        valid_from: Optional["datetime"] = None,
    ) -> Indicator:
        """Make indicator stix object."""
        stix_pattern = f"ipv4-addr:value = '{self.value}'"
        return Indicator(
            name=self.value,
            description=self.description,
            indicator_types=None,
            pattern_type="stix",
            pattern=stix_pattern,
            platforms=None,
            valid_from=valid_from,
            valid_until=None,
            kill_chain_phases=None,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
            observable_type="ipv4-addr",
            score=self.score,
        )


class EmailAddress(Observable):
    """Represent an Email Address observable."""

    display_name: Optional[str] = Field(None, description="Display name.")
    value: EmailStr = Field(..., description="The Email address value.", min_length=1)

    def to_stix2_object(self) -> stix2.v21.EmailAddress:
        """Make stix object."""
        return stix2.EmailAddress(
            # id = auto set for Observable
            value=self.value,
            display_name=self.display_name,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            belongs_to_ref=None,  # belongs to user-account not used
            granular_markings=None,
            defanged=None,
            # custom
            custom_properties=self.custom_properties_to_stix(),
        )

    def to_indicator(
        self,
        valid_from: Optional["datetime"] = None,
        valid_until: Optional["datetime"] = None,
    ) -> Indicator:
        """Make indicator stix object."""
        stix_pattern = f"[email-addr:value = '{self.value}']"
        return Indicator(
            name=self.value,
            description=self.description,
            indicator_types=None,
            pattern_type="stix",
            pattern=stix_pattern,
            platforms=None,
            valid_from=valid_from,
            valid_until=valid_until,
            kill_chain_phases=None,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
            observable_type="email-addr",
            score=self.score,
        )


class EmailMessage(Observable):
    """Represent an Email Message observable.

    Example:
        >>> email_message = EmailMessage(
        ...     attribute_date=datetime.now(),
        ...     body="This is a test email",
        ...     content_type="text/plain",
        ...     is_multipart=True,
        ...     message_id="123456",
        ...     received_lines=2,
        ...     subject="Test Email",
        ...     from_=EmailAddress(value="hacker@example.com"),
        ...     to_=[EmailAddress(value="target@example.com")],
        ...     cc_=None,
        ...     bcc_=None,
        ...     author=OrganizationAuthor(name="author"),
        ...     markings=[TLPMarking(level="white")],
        ...     external_references=None,
        ...     score=None,
        ... )

    """

    # OCTI fields
    attribute_date: Optional[datetime] = Field(
        None, description="Attribute date of the email message."
    )
    body: Optional[str] = Field(None, description="Body of the email message.")
    content_type: Optional[str] = Field(
        None, description="Content type of the email message."
    )
    is_multipart: bool = Field(..., description="Is the email message multipart.")
    message_id: Optional[str] = Field(
        None, description="Message ID of the email message."
    )
    received_lines: Optional[list[str]] = Field(
        None, description="Received lines of the email message."
    )
    subject: str = Field(..., description="Subject of the email message.")

    # Nested relationships
    from_: Optional[EmailAddress] = Field(None, description="From email address.")
    to_: Optional[list[EmailAddress]] = Field(None, description="To email addresses.")
    cc_: Optional[list[EmailAddress]] = Field(None, description="CC email addresses.")
    bcc_: Optional[list[EmailAddress]] = Field(None, description="BCC email addresses.")

    def to_stix2_object(self) -> stix2.v21.EmailMessage:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.EmailMessage(
            is_multipart=self.is_multipart,
            date=self.attribute_date,
            content_type=self.content_type,
            from_ref=self.from_.id if self.from_ else None,
            sender_ref=self.from_.id if self.from_ else None,
            to_refs=[email.id for email in self.to_ or []],
            cc_refs=[email.id for email in self.cc_ or []],
            bcc_refs=[email.id for email in self.bcc_ or []],
            message_id=self.message_id,
            subject=self.subject,
            received_lines=self.received_lines,
            body=self.body,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            additional_header_fields=None,
            body_multipart=None,
            raw_email_ref=None,
            granular_markings=None,
            defanged=None,
            # customs
            custom_properties=self.custom_properties_to_stix(),
        )

    def to_indicator(
        self,
        valid_from: Optional["datetime"] = None,
        valid_until: Optional["datetime"] = None,
    ) -> Indicator:
        """Make indicator stix object."""
        stix_pattern = f"[email-message:subject = '{self.subject}']"
        return Indicator(
            name=self.subject,
            description=self.description,
            indicator_types=None,
            pattern_type="stix",
            pattern=stix_pattern,
            platforms=None,
            valid_from=valid_from,
            valid_until=valid_until,
            kill_chain_phases=None,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
            observable_type="email-message",
            score=self.score,
        )
