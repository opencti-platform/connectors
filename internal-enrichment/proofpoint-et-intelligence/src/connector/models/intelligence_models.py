import re
from datetime import date, datetime
from ipaddress import IPv4Address
from typing import Annotated, Generic, Optional, TypeVar

from pydantic import AfterValidator, BaseModel, Field, PositiveInt

T = TypeVar("T")

domain_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
)
md5_regex = re.compile(r"^[a-f0-9]{32}$")
sha256_regex = re.compile(r"^[a-f0-9]{64}$")


def _check_domain_name(value: str) -> str:
    """Checks if the given value is a valid domain name.
    Args:
        value (str): The domain name to validate.
    Returns:
        str: The valid domain name if it matches the regex pattern.
    Notes:
        regex : "^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
    """
    if domain_regex.match(value):
        return value
    raise ValueError(f"The provided value '{value}' is not a valid domain name.")


def _check_md5(value: str) -> str:
    """Checks if the given value is a valid hash MD5.
    Args:
        value (str): The hash MD5 to validate.
    Returns:
        str: The valid hash MD5 if it matches the regex pattern.
    Notes:
        regex : "^[a-f0-9]{32}$"
    """
    if md5_regex.match(value):
        return value
    raise ValueError(f"The provided value '{value}' is not a valid hash MD5.")


def _check_sha256(value: str) -> str:
    """Checks if the given value is a valid hash SHA256.
    Args:
        value (str): The hash SHA256 to validate.
    Returns:
        str: The valid hash SHA256 if it matches the regex pattern.
    Notes:
        regex : "^[a-f0-9]{64}$"
    """
    if sha256_regex.match(value):
        return value
    raise ValueError(f"The provided value '{value}' is not a valid hash SHA256.")


DomainName = Annotated[str, AfterValidator(_check_domain_name)]
FileMD5 = Annotated[str, AfterValidator(_check_md5)]
FileSHA256 = Annotated[str, AfterValidator(_check_sha256)]


class Ipv4ParameterModel(BaseModel):
    ip: IPv4Address = Field(..., description="The IP associated with the domain.")
    first_seen: date = Field(
        ..., description="The date the IP was first seen associated with the domain."
    )
    last_seen: date = Field(
        ..., description="The date the IP was last seen associated with the domain."
    )


class FileDetailsParameterModel(BaseModel):
    md5sum: FileMD5 = Field(..., description="The MD5 hash of the binary.")
    submit_date: datetime = Field(
        ...,
        description="The date and time the file was originally submitted to Emerging Threats; format is yyyy-MM-dd HH:mm:ss.",
    )
    file_type: Optional[str] = Field(None, description="The type of file.")
    file_size: Optional[PositiveInt] = Field(
        None, description="The size of the binary in bytes."
    )
    sha256: Optional[FileSHA256] = Field(
        None, description="The SHA-256 hash of the binary."
    )


class ReputationParameterModel(BaseModel):
    category: str = Field(
        ..., description="The category of reputation under which this score falls."
    )
    score: PositiveInt = Field(
        ..., ge=0, le=127, description="The numerical reputation score (0-127)."
    )


class DomainParameterModel(BaseModel):
    domain: DomainName = Field(..., description="The domain associated with the IP.")
    first_seen: date = Field(
        ..., description="The date the domain was first seen associated with the IP."
    )
    last_seen: date = Field(
        ..., description="The date the domain was last seen associated with the IP."
    )


class FileParameterModel(BaseModel):
    source: FileMD5 = Field(..., description="The md5sum of the malware sample.")
    first_seen: date = Field(
        ...,
        description="The date the malware sample was first seen associated with the IP.",
    )
    last_seen: date = Field(
        ...,
        description="The date the malware sample was last seen associated with the IP.",
    )


class GeolocationParameterModel(BaseModel):
    ip: IPv4Address = Field(..., description="The IP address specified.")
    country_code: str = Field(
        ...,
        min_length=2,
        max_length=2,
        description="The two-character ISO 3166-1 alpha-2 country code in which the IP was last observed.",
    )
    country: Optional[str] = Field(
        None, description="The country in which the IP was last observed."
    )
    region: Optional[str] = Field(
        None,
        description="A two-character ISO-3166-2 or FIPS 10-4 code for the state or region associated with the IP.",
    )
    city: Optional[str] = Field(
        None, description="The city or town name associated with the IP."
    )
    latitude: Optional[float] = Field(
        None, description="The latitude associated with the IP."
    )
    longitude: Optional[float] = Field(
        None, description="The longitude associated with the IP."
    )


class AsnParameterModel(BaseModel):
    asn: PositiveInt = Field(
        ..., description="The 16 bit autonomous system number (ASN)."
    )
    owner: str = Field(..., description="The owner of the ASN.")
    authorizer: Optional[str] = Field(
        None, description="The authorizing body of the ASN."
    )
    country: Optional[str] = Field(None, description="The country of origin.")
    registration_date: Optional[str] = Field(
        None, description="The date of ASN registration."
    )
    reverse_lookup: Optional[str] = Field(
        None, description="The reverse lookup address for an ASN."
    )


class BaseResponseModel(BaseModel, Generic[T]):
    success: bool = Field(..., description="Indicates if the request was successful.")
    payload: T = Field(..., alias="response", description="Response payload.")
    message: Optional[str] = Field(
        default=None, description="Indicates an error message in certain cases."
    )


class Ipv4ResponseModel(BaseResponseModel[list[Ipv4ParameterModel]]):
    """Response model for IPv4 intelligence"""


class FileDetailsResponseModel(BaseResponseModel[FileDetailsParameterModel]):
    """Response model for File details intelligence"""


class ReputationResponseModel(BaseResponseModel[list[ReputationParameterModel]]):
    """Response model for Reputation intelligence"""


class DomainResponseModel(BaseResponseModel[list[DomainParameterModel]]):
    """Response model for Domain intelligence"""


class FileResponseModel(BaseResponseModel[list[FileParameterModel]]):
    """Response model for File intelligence"""


class GeolocationResponseModel(BaseResponseModel[list[GeolocationParameterModel]]):
    """Response model for Geolocation intelligence"""


class AsnResponseModel(BaseResponseModel[AsnParameterModel]):
    """Response model for ASN intelligence"""
