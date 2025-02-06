"""Offer python client and response models for the TAP Threat API."""

from typing import TYPE_CHECKING, Literal, Optional
from urllib.parse import urljoin

from proofpoint_tap.client_api.common import BaseClient, ResponseModel
from proofpoint_tap.warnings import PermissiveLiteral, Recommended
from pydantic import AwareDatetime, Field

if TYPE_CHECKING:
    from yarl import URL


class Actor(ResponseModel):
    """Model Actor from /v2/threat/summary/<threatId> response."""

    id: str = Field(
        ..., description="The unique identifier of the actor associated with the threat"
    )
    name: str = Field(
        ..., description="The name of the actor associated with the threat"
    )


class Family(ResponseModel):
    """Model Family from /v2/threat/summary/<threatId> response."""

    id: str = Field(..., description="The unique identifier of the threat family")
    name: str = Field(..., description="The name of the threat family")


class Malware(ResponseModel):
    """Model Malware from /v2/threat/summary/<threatId> response."""

    id: str = Field(
        ...,
        description="The unique identifier of the malware associated with the threat",
    )
    name: str = Field(
        ..., description="The name of the malware associated with the threat"
    )


class Technique(ResponseModel):
    """Model Technique from /v2/threat/summary/<threatId> response."""

    id: str = Field(
        ...,
        description="The unique identifier of the technique associated with the threat",
    )
    name: str = Field(
        ..., description="The name of the technique associated with the threat"
    )


class Brand(ResponseModel):
    """Model Brand from /v2/threat/summary/<threatId> response."""

    id: str = Field(
        ..., description="The unique identifier of the brand associated with the threat"
    )
    name: str = Field(
        ..., description="The name of the brand associated with the threat"
    )


class ThreatSummary(ResponseModel):
    """Model ThreatSummary from /v2/threat/summary/<threatId> response.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Threat_API [consulted on December 12, 2024]
    """

    id: str = Field(..., description="A unique threat ID")
    identified_at: AwareDatetime = Field(
        ...,
        alias="identifiedAt",
        description="The time when Proofpoint identified the threat",
    )
    name: str = Field(..., description="The name of the threat")
    type: Recommended[str] = Field(
        None, description="The type of threat (attachment, url, or message text)"
    )
    category: Recommended[str] = Field(
        None,
        description="The category of the threat (impostor, malware, phish, or spam)",
    )
    status: PermissiveLiteral[Literal["active", "cleared", "falsePositive"]] = Field(
        ..., description="The status of the threat (active or cleared)"
    )
    detection_type: Optional[str] = Field(
        None, alias="detectionType", description="The type of detection for the threat"
    )
    severity_score: Recommended[int] = Field(
        None,
        alias="severityScore",
        description="The threat severity score ranging from 0 to 1000",
    )
    attack_spread: Recommended[int] = Field(
        None,
        alias="attackSpread",
        description="The number of Proofpoint customers that received this threat",
    )
    notable: Recommended[bool] = Field(
        None,
        description="Whether the threat is marked as notable by Proofpoint's Threat Analysts",
    )
    vertically_targeted: Recommended[bool] = Field(
        None,
        alias="verticallyTargeted",
        description="Whether the threat is identified as vertically targeted",
    )
    geo_targeted: Recommended[bool] = Field(
        None,
        alias="geoTargeted",
        description="Whether the threat is identified as geographically targeted",
    )
    actors: list[Actor] = Field(
        ..., description="A list of actors associated with the threat"
    )
    families: list[Family] = Field(
        ..., description="A list of threat families associated with the threat"
    )
    malware: list[Malware] = Field(
        ..., description="A list of malware associated with the threat"
    )
    techniques: list[Technique] = Field(
        ..., description="A list of techniques associated with the threat"
    )
    brands: list[Brand] = Field(
        ..., description="A list of brands associated with the threat"
    )


class ThreatClient(BaseClient):
    """Client for the TAP Threat API.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Threat_API [consulted on December 12, 2024]

    Examples:
        >>> import asyncio
        >>> import os
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = ThreatClient(
        ...     os.environ["TAP_BASE_URL"],
        ...     os.environ["TAP_PRINCIPAL"],
        ...     os.environ["TAP_SECRET"],
        ...     int(os.environ["TAP_TIMEOUT"]),
        ...     int(os.environ["TAP_RETRY"]),
        ...     int(os.environ["TAP_BACKOFF"]),
        ... )
        >>> threat_summary = asyncio.run(
        ...     client.fetch_threat_summary(
        ...         "985e627c4f19c0aa9f140641b127c51674b7d4e9cf5d769842458dd23fb806ba"
        ... )

    """

    def _build_threat_summary_query(self, threat_id: str) -> "URL":
        """Build the query URL for fetching threat summary.

        Args:
            threat_id (str): The unique identifier of the threat.

        Returns:
            url: The query URL.

        """
        return self.format_get_query(path=urljoin("/v2/threat/summary/", threat_id))

    async def fetch_threat_summary(self, threat_id: str) -> ThreatSummary:
        """Fetch the threat summary for a given threat ID.

        Args:
            threat_id (str): The unique identifier of the threat.

        Returns:
            ThreatSummary: The threat details.

        """
        query_url = self._build_threat_summary_query(threat_id)
        return ThreatSummary.model_validate(
            await self.get(  # Explicit cast for typing purposes
                query_url=query_url, response_model=ThreatSummary
            )
        )
