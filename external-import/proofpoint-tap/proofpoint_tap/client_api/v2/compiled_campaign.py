"""Offer python client and response models for the ProofPoint TAP compiled campaign.

This merges Campaign, Threat and Forensics API to provide a compiled view of a campaign.

"""

import asyncio
from typing import TYPE_CHECKING, Sequence

from proofpoint_tap.client_api.v2.campaign import (
    CampaignClient,
    CampaignDetailsResponse,
    CampaignMember,
)
from proofpoint_tap.client_api.v2.forensics import Forensics, ForensicsClient
from proofpoint_tap.client_api.v2.threat import ThreatClient, ThreatSummary
from pydantic import Field

if TYPE_CHECKING:
    from datetime import timedelta

    from yarl import URL


class CampaignMemberCompiledInfo(CampaignMember, ThreatSummary):
    """Compile information about a campaign member/threat."""


class CampaignCompiledInfo(CampaignDetailsResponse):
    """Compile information about a campaign with its members and threats."""

    campaign_members: Sequence[CampaignMemberCompiledInfo] = Field(
        ..., description="List of campaign members", alias="campaignMembers"
    )
    forensics: Forensics = Field(..., description="List of forensic reports")


class TAPCompiledCampaignClient:
    """Client to interact with the TAP API.

    Examples:
        >>> import asyncio
        >>> import os
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = TAPCompiledCampaignClient(
        ...     base_url=URL(os.environ["TAP_BASE_URL"]),
        ...     principal=os.environ["TAP_PRINCIPAL"],
        ...     secret=os.environ["TAP_SECRET"],
        ...     timeout=timedela(seconds=float(os.environ["TAP_TIMEOUT"])),
        ...     retry=int(os.environ["TAP_RETRY"]),
        ...     backoff=timedelta(seconds=float(os.environ["TAP_BACKOFF"])),
        ... )
        >>> campaign_id = "90116999-337f-40e0-a25f-e17ae1d8a4f4"
        >>> results = asyncio.run(client.fetch_campaign(campaign_id))

        # Example of fetching campaigns in a time interval
        # Beware this will be quota consumming
        >>> start_datetime = datetime.datetime.fromisoformat("2024-10-01T00:00:00Z")
        >>> end_datetime = datetime.datetime.fromisoformat("2024-10-31T23:59:59Z")
        >>> intervals = [
        ...     (start_datetime + datetime.timedelta(days=i), start_datetime + datetime.timedelta(days=i+1))
        ...     for i in range((end_datetime - start_datetime).days)
        ... ]
        >>> for start, stop in intervals:
        ...     campaingn_ids  = asyncio.run(client.campaign.fetch_campaign_ids(start_time=start, stop_time=stop))
        ...     for campaign_id in campaingn_ids:
        ...         results = asyncio.run(client.fetch_campaign
        ...     )

    """

    def __init__(
        self,
        base_url: "URL",
        principal: str,
        secret: str,
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
    ):
        """Initialize the client
        Args:
            base_url (str): The base URL of the TAP API.
            principal (str): The principal to authenticate with the API.
            secret (str): The secret to authenticate with the API.
            timeout (int): The timeout for the API requests in seconds.

        """
        common_kwargs = dict(  # noqa: C408  # keep dict constructor rather than literal dict for maintainance.
            base_url=base_url,
            principal=principal,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
        )

        # we deserialize instead of repeating kwargs
        self.campaign = CampaignClient(**common_kwargs)  # type:ignore[arg-type]
        self.threat = ThreatClient(**common_kwargs)  # type:ignore[arg-type]
        self.forensics = ForensicsClient(**common_kwargs)  # type:ignore[arg-type]

    async def fetch_campaign(self, campaign_id: str) -> CampaignCompiledInfo:
        """Fetch the details of a campaign and compile additional information.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            CampaignAggregatedInfo: The campaign details with additional information.

        """
        task_campaign_details = asyncio.create_task(
            self.campaign.fetch_campaign_details(campaign_id)
        )
        task_forensics = asyncio.create_task(
            self.forensics.fetch_forensics(campaign_id=campaign_id)
        )
        # Await the needed campaign details to launch threats retrieval
        campaign_details = await task_campaign_details
        tasks_threats = [
            asyncio.create_task(self.threat.fetch_threat_summary(member.id))
            for member in campaign_details.campaign_members
        ]

        # Await the threats and forensics to enrich campaign
        apis_results = await asyncio.gather(*tasks_threats, task_forensics)

        threat_summaries = apis_results[:-1]
        forensics = apis_results[-1]

        # We manipulate the description as dict to include the threat summary and forensics
        holder = campaign_details.model_dump(by_alias=True)
        for index, summary in enumerate(threat_summaries):
            holder["campaignMembers"][index].update(summary.model_dump(by_alias=True))

        holder["forensics"] = forensics.model_dump(by_alias=True)
        return CampaignCompiledInfo.model_validate(holder)
