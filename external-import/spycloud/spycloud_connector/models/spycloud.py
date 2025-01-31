from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

BreachCatalogType = Literal["PRIVATE", "PUBLIC"]
BreachCatalogConfidence = Literal[1, 2, 3]
BreachCatalogMainCategory = Literal["combolist", "breach", "malware"]
BreachRecordSeverity = Literal[2, 5, 20, 25]
BreachRecordWatchlistType = Literal["email", "domain", "subdomain", "ip"]


class BreachCatalog(BaseModel):
    """
    Class for SpyCloud breach catalog.
    Only required fields and those useful for OCTI entities are described explicitly and all extra fields provided by SpyCloud API are ignored.
    See https://spycloud-external.readme.io/sc-data-schema/docs/getting-started#breach-catalog for fields reference.
    """

    model_config: ConfigDict = ConfigDict(extra="ignore", frozen=True)

    id: int = Field(
        description="Numerical breach ID. This number correlates to source_id data point found in breach records.",
    )
    uuid: str = Field(
        description="UUID v4 encoded version of breach ID. This is relevant for users of Firehose, where each deliverable (records file) is named using the breach UUID.",
    )
    title: str = Field(
        description="Breach title. For each ingested breach our security research team documents a breach title. This is only available when we can disclose the breach details, otherwise it will have a generic title.",
    )
    description: str = Field(
        description="Breach description. For each ingested breach our security research team documents a breach description. This is only available when we can disclose the breach details, otherwise it will have a generic description.",
    )
    type: BreachCatalogType = Field(
        description="Denotes if a breach is considered public or private. A public breach is one that is easily found on the internet, while a private breach is often exclusive to SpyCloud.",
    )
    num_records: int = Field(
        description="Number of records we parsed and ingested from this particular breach. This is after parsing, normalization and deduplication take place.",
    )
    spycloud_publish_date: datetime = Field(
        description="The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers.",
    )
    acquisition_date: datetime = Field(
        description="The date on which our security research team first acquired the breached data.",
    )
    assets: dict = Field(
        description="Dictionary field. A mapping of assets to count for this particular breach.",
    )
    confidence: BreachCatalogConfidence = Field(
        description="Numerical score representing the confidence in the source of the breach.",
    )
    breach_main_category: BreachCatalogMainCategory = Field(
        description="Categorizes breach into combolist, breach, or malware."
    )
    breach_category: str = Field(
        description="Categorizes how the data was breached.",
    )
    sensitive_source: bool = Field(
        description="Indicates whether a breach source is sensitive or not.",
    )
    consumer_category: str = Field(
        description="Categorization for consumer product mapping.",
    )
    tlp: str = Field(
        description="Traffic light protocol. TLP is a set of designations used to ensure that sensitive information is shared with the appropriate audience.",
    )
    short_title: str = Field(
        description="Shortened version of title field when necessary.",
    )


class BreachRecord(BaseModel):
    """
    Class for SpyCloud breach records.
    Only required fields and those useful for OCTI entities are described explicitly but all extra fields provided by Spycloud API are allowed.
    Extra fields are all optional and _might_ be present in API response.
    See https://spycloud-external.readme.io/sc-data-schema/docs/getting-started#breach-records for fields reference.
    """

    model_config: ConfigDict = ConfigDict(extra="allow", frozen=True)

    document_id: str = Field(
        description="UUID v4 string which uniquely identifies this breach record in our data set.",
    )
    source_id: int = Field(
        description="Numerical breach ID. This correlates directly with the id field in Breach Catalog objects.",
    )
    spycloud_publish_date: datetime = Field(
        description="The date on which this record was ingested into our systems. In ISO 8601 datetime format. This correlates with spycloud_publish_date field in Breach Catalog objects.",
    )
    severity: BreachRecordSeverity = Field(
        description="Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned.",
    )

    email: Optional[str] = Field(
        description="User email address.",
        default=None,
    )
    full_name: Optional[str] = Field(
        description="User full name.",
        default=None,
    )
    ip_addresses: Optional[list[str]] = Field(
        description="List of one or more IP addresses in alphanumeric format. Both IPV4 and IPv6 addresses are supported.",
        default=None,
    )
    infected_path: Optional[str] = Field(
        description="The local path to the malicious software installed on the infected user's system.",
        default=None,
    )
    mac_address: Optional[str] = Field(
        description="A unique, 12-character alphanumeric attribute used to identify individual electronic devices on a network.",
        default=None,
    )
    target_domain: Optional[str] = Field(
        description="SLD extracted from 'target_url' field.",
        default=None,
    )
    target_subdomain: Optional[str] = Field(
        description="Subdomain and SLD extracted from 'target_url' field.",
        default=None,
    )
    target_url: Optional[str] = Field(
        description="URL extracted from Botnet data. This is the URL that is captured from a key logger installed on an infected user's system.",
        default=None,
    )
    user_agent: Optional[str] = Field(
        description="Browser agent string.",
        default=None,
    )
    user_hostname: Optional[str] = Field(
        description="System hostname. This usually comes from Botnet data.",
        default=None,
    )
    user_os: Optional[str] = Field(
        description="System OS name. This usually comes from Botnet data.",
        default=None,
    )
    username: Optional[str] = Field(
        description="Username.",
        default=None,
    )

    # more optional fields are available in API response but not described here.
