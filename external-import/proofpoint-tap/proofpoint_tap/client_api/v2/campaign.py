"""Offer python client and response models for the TAP Campaign API."""

from datetime import datetime, timedelta
from logging import getLogger
from typing import TYPE_CHECKING, Literal, Optional, Sequence
from urllib.parse import urljoin

from proofpoint_tap.client_api.common import BaseClient, ResponseModel
from proofpoint_tap.errors import (
    ProofpointAPI404NoReasonError,
    ProofPointAPIRequestParamsError,
)
from proofpoint_tap.warnings import PermissiveLiteral, Recommended
from pydantic import AwareDatetime, Field

if TYPE_CHECKING:
    from yarl import URL

logger = getLogger(__name__)


class Campaign(ResponseModel):
    """Model /v2/campaign/ids response.

    Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    id: str = Field(..., description="Campaign ID")
    last_updated_at: AwareDatetime = Field(
        ..., description="Last updated timestamp of the campaign", alias="lastUpdatedAt"
    )


class CampaignIdsResponse(ResponseModel):
    """Model /v2/campaign/ids response.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    campaigns: list[Campaign] = Field(..., description="List of campaigns")


# Models for /v2/campaign/<campaignId> response
class Actor(ResponseModel):
    """Model Actor from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the actor")
    id: str = Field(..., description="Actor identifier")


class Malware(ResponseModel):
    """Model Malware from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the malware family")
    id: str = Field(..., description="Malware family identifier")


class Technique(ResponseModel):
    """Model Technique from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the technique")
    id: str = Field(..., description="Technique identifier")


class Family(ResponseModel):
    """Model Family. Rather defined in /v2/threat/summary/<threatId> documentation."""

    id: str = Field(..., description="The unique identifier of the threat family")
    name: str = Field(..., description="The name of the threat family")


class Brand(ResponseModel):
    """Model Brand. Rather defined in /v2/threat/summary/<threatId> documentation."""

    id: str = Field(
        ..., description="The unique identifier of the brand associated with the threat"
    )
    name: str = Field(
        ..., description="The name of the brand associated with the threat"
    )


class CampaignMember(ResponseModel):
    """Model CampaignMember from /v2/campaign/<campaignId> response."""

    id: str = Field(..., description="Threat identifier")
    threat: str = Field(
        ..., description="Attachment hash or URL fragment of the threat"
    )
    type: Recommended[str] = Field(
        None, description="The type of threat (attachment, url, or message text)"
    )
    sub_type: Optional[str] = Field(
        None,
        description="Sub-type of the threat: ATTACHMENT, COMPLETE_URL, etc.",
        alias="subType",
    )
    threat_time: AwareDatetime = Field(
        ...,
        description="Datetime the threat variant was first recognized as malicious",
        alias="threatTime",
    )
    threat_status: PermissiveLiteral[Literal["active", "cleared", "falsePositive"]] = (
        Field(..., description="Status of the threat.", alias="threatStatus")
    )


class CampaignDetailsResponse(ResponseModel):
    """Model /v2/campaign/<campaignId> response.

    Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    id: str = Field(..., description="Campaign ID")
    name: str = Field(..., description="Name of the campaign")
    description: str = Field(..., description="Description of the campaign")
    start_date: AwareDatetime = Field(
        ...,
        description="Start date of the campaign in ISO8601 format",
        alias="startDate",
    )
    campaign_members: Sequence[CampaignMember] = Field(
        ..., description="List of campaign members", alias="campaignMembers"
    )
    actors: Optional[Sequence[Actor]] = Field(
        None, description="List of actors associated with the campaign"
    )
    malware: Optional[Sequence[Malware]] = Field(
        None, description="List of malware families associated with the campaign"
    )
    techniques: Optional[Sequence[Technique]] = Field(
        None, description="List of techniques used in the campaign"
    )
    notable: Recommended[bool] = Field(None, description="Undocumented.")
    families: Optional[Sequence[Family]] = Field(None, description="Undocumented.")
    brands: Optional[Sequence[Brand]] = Field(None, description="Undocumented.")


# Client class
class CampaignClient(BaseClient):
    """Client to interact with the TAP Campaign API.

    Reference:
            https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]

    Exemples:
        >>> import asyncio
        >>> import os
        >>> from datetime import datetime, timezone
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = CampaignClient(
        ...     base_url=URL(os.environ["TAP_BASE_URL"]),
        ...     principal=os.environ["TAP_PRINCIPAL"],
        ...     secret=os.environ["TAP_SECRET"],
        ...     timeout=timedelta(seconds=float(os.environ["TAP_TIMEOUT"])),
        ...     retry=int(os.environ["TAP_RETRY"]),
        ...     backoff=timedelta(seconds=float(os.environ["TAP_BACKOFF"])),
        ... )
        >>> start_time = datetime(2023, 12, 13, tzinfo=timezone.utc)
        >>> end_time = datetime(2023, 12, 13, 12, 00, 00, tzinfo=timezone.utc)
        >>> async def use_case_get_campaigns_details(
        ...     client: CampaignClient, start_time: datetime, end_time: datetime
        ... ) -> list[CampaignDetailsResponse]:
        ...     holders = []
        ...     ids_response = await client.fetch_campaign_ids(
        ...         start_time, end_time
        ...     )
        ...     for campaign in ids_response.campaigns:
        ...         campaign_id = campaign.id
        ...         details_response = await client.fetch_campaign_details(campaign_id)
        ...         holders.append(details_response)
        ...     return holders
        >>> campaigns_details = asyncio.run(
        ...     use_case_get_campaigns_details(client, start_time, end_time)
        ... )

    """

    @staticmethod
    def _format_interval_param(start_time: datetime, end_time: datetime) -> str:
        """Format the interval parameter for the query URL."""
        if (end_time - start_time) > timedelta(hours=24):
            raise ProofPointAPIRequestParamsError(
                "The interval between start_time and end_time should be less than 24 hours."
            )
        if start_time > end_time:
            raise ProofPointAPIRequestParamsError(
                "The end_time should be greater than the start_time."
            )
        return f"{start_time.isoformat()}/{end_time.isoformat()}"

    def _build_campaign_ids_query(
        self,
        start_time: datetime,
        end_time: datetime,
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> "URL":
        """Build the query URL for fetching campaign IDs.

        Args:
            start_time(datetime.datetime): Start time of the interval
            end_time(datetime.datetime): End time of the interval
            size (Optional[int]): Number of records to fetch
            page (Optional[int]): The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1

        Returns:
            (URL): The query URL.

        """
        interval = CampaignClient._format_interval_param(start_time, end_time)

        if size is not None and size > 200:
            raise ProofPointAPIRequestParamsError(
                "The maximum allowed value for size is 200."
            )

        query_params = {"interval": interval, "size": size, "page": page}
        # Remove None values from query_params
        query_params = {k: v for k, v in query_params.items() if v is not None}
        return self.format_get_query("/v2/campaign/ids", query_params)

    def _build_campaign_details_query(self, campaign_id: str) -> "URL":
        """Build the query URL for fetching campaign details.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            (URL): The query URL.

        """
        return self.format_get_query(path=urljoin("/v2/campaign/", campaign_id))

    async def fetch_campaign_ids(
        self,
        start_time: datetime,
        end_time: datetime,
        page: Optional[int] = None,
        size: Optional[int] = None,
    ) -> CampaignIdsResponse:
        """Fetch the campaign IDs.

        Args:
            start_time (datetime): Start time of the interval
            end_time (datetime): End time of the interval
            page (Optional[int]): The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1
            size (Optional[int]): Number of records to fetch

        Returns:
            CampaignIdsResponse: The campaign IDs response.

        Raises:
            ProofPointAPIRequestParamsError: If the interval between start_time and end_time is more than 24 hours.
            ProofPointAPIRequestParamsError: If the maximum allowed value for size is more than 200.
            ProofpointAPI404NoReasonError: If the API returns a 404 status code with no reason. This may be due to no data in Proofpoint side.


        """
        query_url = self._build_campaign_ids_query(start_time, end_time, page, size)
        try:
            response_model_instance = await self.get(query_url, CampaignIdsResponse)
            return CampaignIdsResponse.model_validate(
                response_model_instance
            )  # Explicit cast for typing purposes
        except ProofpointAPI404NoReasonError as e:
            # Unfortunately sometimes the 404 Error is due to no data in the specified time range from proofpoint side
            # This occured with /v2/campaign/ids?interval=2024-10-05T00:00:00%2B00:00/2024-10-06T00:00:00%2B00:00 for instance.
            # Technical decision logs:
            # * KO : Due to quota limitation, we will not try to `ping` another time window to see if it is a real 404 or just a no data error.
            # * KO : We will not except any Assertion or 404 Error and create an empty CampaignIdsResponse that would hide a wrong base_url parmeters.
            # * OK : We will raise a ProofpointAPIError error subclass with a message that explains the specific situation and the potential cause.
            message = f"Failed to fetch campaign IDs, this may be due to no data in Proofpoint side. This seems to happen especially while fetching Saturday and Sunday data {e}"
            logger.error(message)
            raise ProofpointAPI404NoReasonError(message) from e

    async def fetch_campaign_details(self, campaign_id: str) -> CampaignDetailsResponse:
        """Fetch the details of a campaign.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            CampaignDetailsResponse: The campaign details.

        """
        query_url = self._build_campaign_details_query(campaign_id)
        response_model_instance = await self.get(
            query_url=query_url, response_model=CampaignDetailsResponse
        )
        return (
            CampaignDetailsResponse.model_validate(  # Explicit cast for typing purposes
                response_model_instance
            )
        )
