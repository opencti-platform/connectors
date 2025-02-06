"""Implement adapters for Campaign Port."""

import asyncio
from datetime import timedelta
from logging import getLogger
from typing import TYPE_CHECKING, Any, Generator

from proofpoint_tap.client_api.v2.campaign import (
    CampaignClient,
    CampaignDetailsResponse,
    CampaignIdsResponse,
    CampaignMember,
)
from proofpoint_tap.errors import ProofpointAPI404Error, ProofpointAPI404NoReasonError
from proofpoint_tap.ports.campaign import CampaignPort, CampaignsPort, ObservedDataPort

if TYPE_CHECKING:
    from datetime import datetime

    from pydantic import SecretStr
    from yarl import URL


logger = getLogger(__name__)


class ObservedDataAPIV2(ObservedDataPort):
    """Observed data API V2 adapter."""

    def __init__(self, campaign_member: CampaignMember):
        """Initialize the adapter."""
        self._campaign_member = campaign_member

    @property
    def type_(self) -> str:
        """Get the observed data type."""
        return self._campaign_member.type or ""

    @property
    def value(self) -> str:
        """Get the observed data value."""
        return self._campaign_member.threat

    @property
    def observed_at(self) -> "datetime":
        """Get the observed data datetime."""
        return self._campaign_member.threat_time


class CampaignAPIV2(CampaignPort):
    """Campaign API V2 adapter."""

    def __init__(self, details: CampaignDetailsResponse):
        """Initialize the adapter."""
        self._details = details

    @property
    def name(self) -> str:
        """Get the name of the campaign."""
        return self._details.name

    @property
    def start_datetime(self) -> "datetime":
        """Get the start datetime of the campaign."""
        return self._details.start_date

    @property
    def description(self) -> str:
        """Get the description of the campaign."""
        return self._details.description

    @property
    def actor_names(self) -> list[str]:
        """Get the actor names of the campaign."""
        return [actor.name for actor in self._details.actors or []]

    @property
    def malware_names(self) -> list[str]:
        """Get the malware names of the campaign."""
        return [malware.name for malware in self._details.malware or []]

    @property
    def malware_family_names(self) -> list[str]:
        """Get the malware family names of the campaign."""
        return [family.name for family in self._details.families or []]

    @property
    def targeted_brand_names(self) -> list[str]:
        """Get the targeted brand names of the campaign."""
        return [brand.name for brand in self._details.brands or []]

    @property
    def technique_names(self) -> list[str]:
        """Get the technique names of the campaign."""
        return [technique.name for technique in self._details.techniques or []]

    @property
    def observed_data(self) -> list[ObservedDataPort]:
        """Get the observed data of the campaign."""
        observed_data_holder: list[ObservedDataPort] = []
        for campaign_member in self._details.campaign_members:
            observed_data_holder.append(
                ObservedDataAPIV2(campaign_member=campaign_member)
            )
        return observed_data_holder


class CampaignsAPIV2(CampaignsPort):
    """Campaigns API V2 adapter."""

    def __init__(
        self,
        base_url: "URL",
        principal: "SecretStr",
        secret: "SecretStr",
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
    ):
        """Initialize the adapter."""
        self._client = CampaignClient(
            base_url=base_url,
            principal=principal,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
        )

    @staticmethod
    def _chunk_1_day_intervals(
        start_time: "datetime", stop_time: "datetime"
    ) -> Generator[tuple["datetime", "datetime"], Any, Any]:
        """Chunk the requests with time windows of 24 hours.

        Examples:
            >>> from datetime import datetime
            >>> start_time = datetime(2021, 1, 1, 0, 10, 0)
            >>> stop_time = datetime(2021, 1, 4, 0, 20, 0)
            >>> list(CampaignsAPIV2._chunk_1_day_intervals(start_time=start_time, stop_time=stop_time))

        """
        total_days = (stop_time - start_time).days + 1
        for i in range(total_days):
            if start_time + timedelta(days=i) < stop_time:
                yield (
                    start_time + timedelta(days=i),
                    min(start_time + timedelta(days=i + 1), stop_time),
                )

    async def _list(
        self, start_time: "datetime", stop_time: "datetime"
    ) -> CampaignIdsResponse:
        """List the campaigns identifiers."""
        try:
            results = await self._client.fetch_campaign_ids(
                start_time=start_time, end_time=stop_time
            )
        except (ProofpointAPI404Error, ProofpointAPI404NoReasonError) as e:
            # NB: in this particular case it may be due to no data in Proofpoint side.
            logger.warning(str(e))
            return CampaignIdsResponse(campaigns=[])
        return results

    def list(self, start_time: "datetime", stop_time: "datetime") -> list[str]:
        """List the campaigns identifiers."""
        ids = []

        async def _coro() -> list[CampaignIdsResponse]:
            # create async list of tasks
            tasks = [
                self._list(start_time=start, stop_time=stop)
                for start, stop in self._chunk_1_day_intervals(
                    start_time=start_time, stop_time=stop_time
                )
            ]
            # gather results (order is preserved)
            return await asyncio.gather(*tasks)

        # flatten and get ids
        for result in asyncio.run(_coro()):
            for campaign in result.campaigns:
                ids.append(campaign.id)
        return ids

    def details(self, campaign_id: str) -> CampaignPort:
        """Get the campaign details."""
        raw_details = asyncio.run(
            self._client.fetch_campaign_details(campaign_id=campaign_id)
        )
        return CampaignAPIV2(details=raw_details)

    # def bulk_details(self, campaign_ids: Iterable[str]) -> list[CampaignPort]:
    #     """Get the campaign details."""
    #     # create async list of tasks
    #     tasks = [self._list(start_time=start, stop_time=stop) for start, stop in self._chunk_1_day_intervals(start_time=start_time, stop_time=stop_time)]
    #     # gather results (order is preserved)
    #     raw_results = asyncio.run(asyncio.gather(*tasks))
    #     return [CampaignAPIV2(details=raw_details) for raw_details in raw_results]
