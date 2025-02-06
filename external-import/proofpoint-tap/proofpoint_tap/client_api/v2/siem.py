"""Offer python client and response models for the ProofPoint TAP SIEM API."""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, Optional

from proofpoint_tap.client_api.common import BaseClient, ResponseModel
from proofpoint_tap.errors import ProofPointAPIRequestParamsError
from proofpoint_tap.warnings import PermissiveLiteral, Recommended
from pydantic import (
    AwareDatetime,
    EmailStr,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from yarl import URL


class MessagePart(ResponseModel):
    """Model MessagePart from /v2/siem/* responses."""

    content_type: str = Field(
        ...,
        alias="contentType",
        description="The true detected Content-Type of the message part.",
    )
    disposition: Literal["inline", "attached"] = Field(
        ..., description="Disposition of the message part (inline or attached)."
    )
    filename: Optional[str] = Field(
        None, description="The filename of the message part."
    )
    md5: Optional[str] = Field(
        None, description="The MD5 hash of the message part contents."
    )
    sha256: Optional[str] = Field(
        None, description="The SHA256 hash of the message part contents."
    )
    o_content_type: Optional[str] = Field(
        None,
        alias="oContentType",
        description="The declared Content-Type of the message part.",
    )
    sandbox_status: Optional[
        PermissiveLiteral[
            Literal[
                "unsupported",
                "threat",
                "clean",
                "prefilter",
                "uploaded",
                "inprogress",
                "uploaddisabled",
                "NOT_SUPPORTED",
                "CLEAN",
            ]
        ]
    ] = Field(
        None,
        alias="sandboxStatus",
        description="The verdict from sandbox scanning process.\
            Note: NOT_SUPPORTED and CLEAN are not in documentation but can also be returned.",
    )


class ThreatInfo(ResponseModel):
    """Model ThreatInfo from /v2/siem/* responses."""

    actors: Optional[list[dict[Any, Any]]] = Field(
        None, description="List of actors associated with the threat. Undocumented."
    )
    detection_type: Optional[str] = Field(
        None, alias="detectionType", description="Type of detection."
    )
    campaign_id: Optional[str] = Field(
        None,
        alias="campaignID",
        description="Campaign identifier if a campaign has been identified. Note: The documentation specifies campaignId but the API response is campaignID.",
    )
    classification: Literal["malware", "phish", "spam", "impostor", "toad"] = Field(
        ...,
        description="Threat classification.\
        Note: The documentation specifies TOAD classification but the API response is Toad.",
    )
    threat: str = Field(..., description="The artifact condemned by Proofpoint.")
    threat_id: str = Field(
        ...,
        alias="threatID",
        description="Unique identifier of the threat. Note: The documentation specifies threatId but the API response is threatID.",
    )
    threat_status: Literal["active", "falsepositive", "cleared"] = Field(
        ..., alias="threatStatus", description="Current state of the threat."
    )
    threat_time: AwareDatetime = Field(
        ..., alias="threatTime", description="Time the threat was identified."
    )
    threat_type: PermissiveLiteral[Literal["attachment", "message", "messagetext"]] = (
        Field(
            ...,
            alias="threatType",
            description="Type of the threat.\
            Note: The documentation specifies Message but the API response is MessageText.",
        )
    )
    threat_url: Optional[str] = Field(
        None,
        alias="threatUrl",
        description="URL link to the threat on the TAP Dashboard.",
    )

    @field_validator("classification", "threat_type", mode="before")
    @classmethod
    def _lower(cls, value: str) -> str:
        """Lower the values to avoid inconsistent API response content."""
        return value.lower()


class MessageEvent(ResponseModel):
    """Model MessageEvent from /v2/siem/* responses."""

    cc_addresses: Optional[list[EmailStr]] = Field(
        None, alias="ccAddresses", description="List of CC email addresses."
    )
    cluster: str = Field(
        ...,
        description="PPS cluster name. Note: The documentation talks about clusterID but the API response is cluster.",
    )
    completely_rewritten: Optional[bool] = Field(
        None, alias="completelyRewritten", description="URL rewrite status."
    )
    from_address: list[EmailStr] = Field(
        ...,
        alias="fromAddress",
        description="Email address in the From header. Note: The documentation specifies a single email address but the API response is a list.",
    )
    guid: str = Field(..., alias="GUID", description="Unique ID of the message in PPS.")
    header_from: str = Field(
        ..., alias="headerFrom", description="Full content of the From header."
    )
    header_reply_to: Optional[str] = Field(
        None, alias="headerReplyTo", description="Full content of the Reply-To header."
    )
    id: Recommended[str] = Field(None, description="ID of the message in PPS.")
    impostor_score: Optional[int] = Field(
        None,
        alias="impostorScore",
        ge=0,
        le=100,
        description="Impostor score of the message (0-100).",
    )
    malware_score: Optional[int] = Field(
        None,
        alias="malwareScore",
        ge=0,
        le=100,
        description="Malware score of the message (0-100).",
    )
    message_id: Optional[str] = Field(
        None, alias="messageID", description="Message-ID from headers."
    )
    message_parts: list[MessagePart] = Field(
        ..., alias="messageParts", description="Details about message parts."
    )
    message_size: Optional[int] = Field(
        None, alias="messageSize", description="Size of the message in bytes."
    )
    message_time: AwareDatetime = Field(
        ..., alias="messageTime", description="Time the message was processed."
    )
    modules_run: Optional[list[str]] = Field(
        None, alias="modulesRun", description="Modules that processed the message."
    )
    phish_score: Optional[int] = Field(
        None,
        alias="phishScore",
        description="Phish score of the message (0-100).",
        ge=0,
        le=100,
    )
    policy_routes: Optional[list[str]] = Field(
        None,
        alias="policyRoutes",
        description="Policy routes matched during processing.",
    )
    qid: str = Field(..., alias="QID", description="Queue ID of the message in PPS.")
    quarantine_folder: Optional[str] = Field(
        None,
        alias="quarantineFolder",
        description="Quarantine folder name (if quarantined).",
    )
    quarantine_rule: Optional[str] = Field(
        None, alias="quarantineRule", description="Rule that quarantined the message."
    )
    recipient: list[str] = Field(
        ...,
        description="SMTP recipient email address. Note: The documentation specifies a single email address but the API response is a list.",
    )
    reply_to_address: Optional[list[EmailStr]] = Field(
        None,
        alias="replyToAddress",
        description="Email address in the Reply-To header.",
    )
    sender: EmailStr = Field(..., description="SMTP sender email address.")
    sender_ip: str = Field(..., alias="senderIP", description="Sender's IP address.")
    spam_score: Optional[int] = Field(
        None,
        alias="spamScore",
        description="Spam score of the message (0-100).",
        ge=0,
        le=100,
    )
    subject: Optional[str] = Field(None, description="Subject line of the message.")
    threats_info_map: list[ThreatInfo] = Field(
        ..., alias="threatsInfoMap", description="Details about detected threats."
    )
    to_addresses: Optional[list[EmailStr]] = Field(
        None, alias="toAddresses", description="list of To email addresses."
    )
    xmailer: Optional[str] = Field(None, description="Content of the X-Mailer header.")

    @field_validator("completely_rewritten", mode="before")
    @classmethod
    def _format_completely_rewritten(cls, value: str | bool) -> Optional[bool]:
        """Format the completely_rewritten value."""
        return {"true": True, "false": False, "na": None}[str(value).lower()]


class ClickEvent(ResponseModel):
    """Model ClickEvent from /v2/siem/* responses."""

    campaign_id: Optional[str] = Field(
        None, alias="campaignId", description="Campaign identifier."
    )
    classification: PermissiveLiteral[Literal["malware", "phish", "spam"]] = Field(
        ..., description="Threat classification of the URL."
    )
    click_ip: IPvAnyAddress = Field(
        ...,
        alias="clickIP",
        description="External IP of the user who clicked the link.",
    )
    click_time: AwareDatetime = Field(
        ..., alias="clickTime", description="Time the click occurred."
    )
    guid: str = Field(..., alias="GUID", description="Unique ID of the click event.")
    message_id: Optional[str] = Field(
        None, alias="messageID", description="Message-ID from headers."
    )
    recipient: str = Field(..., description="Email recipient.")
    sender: str = Field(..., description="Email sender.")
    sender_ip: IPvAnyAddress = Field(
        ..., alias="senderIP", description="Sender's IP address."
    )
    threat_id: str = Field(
        ..., alias="threatID", description="Details about detected threats."
    )
    threat_time: AwareDatetime = Field(
        ..., alias="threatTime", description="Time the threat was identified."
    )
    threat_url: str = Field(
        ..., alias="threatUrl", description="Theurl to follow for threat description."
    )
    threat_status: Literal["active", "falsepositive", "cleared"] = Field(
        ..., alias="threatStatus", description="Current state of the threat."
    )
    url: str = Field(..., description="The URL clicked by the user.")
    user_agent: str = Field(
        ...,
        alias="userAgent",
        description="User agent of the user who clicked the link.",
    )

    @field_validator("classification", mode="before")
    @classmethod
    def _lower(cls, value: str) -> str:
        """Lower the values to avoid inconsistent API response content."""
        return value.lower()


class SIEMResponse(ResponseModel):
    """Model SIEMResponse from /v2/siem/* responses."""

    query_end_time: AwareDatetime = Field(
        ..., alias="queryEndTime", description="End time of the queried data period."
    )
    messages_delivered: Optional[list[MessageEvent]] = Field(
        None,
        alias="messagesDelivered",
        description="Messages with threats that were delivered.",
    )
    messages_blocked: Optional[list[MessageEvent]] = Field(
        None,
        alias="messagesBlocked",
        description="Messages with threats that were blocked.",
    )
    clicks_permitted: Optional[list[ClickEvent]] = Field(
        None,
        alias="clicksPermitted",
        description="Clicks to malicious URLs that were permitted.",
    )
    clicks_blocked: Optional[list[ClickEvent]] = Field(
        None,
        alias="clicksBlocked",
        description="Clicks to malicious URLs that were blocked.",
    )

    @model_validator(mode="after")
    def _check_at_least_one_events_key(self) -> "SIEMResponse":
        if all(
            event_type is None
            for event_type in [
                self.messages_delivered,
                self.messages_blocked,
                self.clicks_permitted,
                self.clicks_blocked,
            ]
        ):
            raise ValueError(
                "At least one of the following keys must be present: messagesDelivered, messagesBlocked, clicksPermitted, clicksBlocked"
            )
        return self


class SIEMEndpoint(Enum):
    """Enumeration of the SIEM API endpoints."""

    CLICKS_BLOCKED = "/v2/siem/clicks/blocked"
    CLICKS_PERMITTED = "/v2/siem/clicks/permitted"
    MESSAGES_BLOCKED = "/v2/siem/messages/blocked"
    MESSAGES_DELIVERED = "/v2/siem/messages/delivered"
    ISSUES = "/v2/siem/issues"
    ALL = "/v2/siem/all"


class SIEMClient(BaseClient):
    """Client to interact with the TAP SIEM API.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API [consulted on December 12, 2024]

    Exemple:
        >>> # Retrieve all events for the last hour
        >>> import asyncio
        >>> import os
        >>> from datetime import datetime, timedelta
        >>> from dotenv import load_dotenv
        >>> from yarl import URL
        >>> _ = load_dotenv()
        >>> client = SIEMClient(
        ...     base_url=URL(os.environ["TAP_BASE_URL"]),
        ...     principal=os.environ["TAP_PRINCIPAL"],
        ...     secret=os.environ["TAP_SECRET"],
        ...     timeout=timedelta(seconds=float(os.environ["TAP_TIMEOUT"])),
        ...     retry=int(os.environ["TAP_RETRY"]),
        ...     backoff=timedelta(seconds=float(os.environ["TAP_BACKOFF"])),
        ... )
        >>> end_time = datetime.now(timezone.utc)
        >>> start_time = end_time - timedelta(hours=1)
        >>> results = asyncio.run(client.fetch_all(start_time, end_time))

    """

    RESPONSE_FORMAT_REQUEST = Literal["syslog", "JSON"]
    THREAT_TYPE_REQUEST = Optional[Literal["url", "attachment", "messageText"]]
    THREAT_STATUS_REQUEST = Optional[Literal["active", "cleared", "falsePositive"]]

    @staticmethod
    def _format_interval_param(start_time: "datetime", end_time: "datetime") -> str:
        """Format the interval parameter for the query URL."""
        if start_time.tzinfo is None or end_time.tzinfo is None:
            raise ProofPointAPIRequestParamsError(
                "Both start_time and end_time must be timezone aware."
            )

        now_utc = datetime.now(timezone.utc)
        if start_time < (now_utc - timedelta(hours=168)):
            raise ProofPointAPIRequestParamsError(
                "The start_time must be within the last 168 hours (7 days)."
            )

        if end_time > now_utc:
            # NOTA BENE: We noticed that sometimes the API still answers 400 error with message
            # "The requested interval is still current." despite this check.
            raise ProofPointAPIRequestParamsError("The end_time must be in the past.")

        if end_time < start_time:
            # API answers 400 error code without error description.
            raise ProofPointAPIRequestParamsError(
                "The end_time must be greater than the start_time."
            )

        if (end_time - start_time) > timedelta(hours=1):
            raise ProofPointAPIRequestParamsError(
                "The time range must be less than 1 hour."
            )

        return f"{start_time.isoformat()}/{end_time.isoformat()}"

    def _handle_params(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> dict[str, str]:
        """Handle the query parameters.

        Note:
            The V2 siem API provides 3 way to handle time range (sinceSeconds, sinceTime, interval).
            We only use interval here.

        """
        params = {
            "format": response_format,
            "interval": self._format_interval_param(start_time, end_time),
        }
        if threat_type:
            params["threatType"] = threat_type
        if threat_status:
            params["threatStatus"] = threat_status
        return params

    def _build_query(
        self,
        endpoint: SIEMEndpoint,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> "URL":
        """Build a query for events in the specified time period.

        Args:
            endpoint (SIEMEndpoint): The endpoint to query.
            start_time (datetime): The start time of the events.
            end_time (datetime): The end time of the events.
            response_format (str): The format in which data is returned. Default is JSON.
            threat_type (str): The threat type to return in the data. Default is None.
            threat_status (str): The threat status to return in the data. Default is None.

        Returns:
            (URL): The formatted URL.

        """
        return self.format_get_query(
            path=endpoint.value,
            params=self._handle_params(
                start_time=start_time,
                end_time=end_time,
                response_format=response_format,
                threat_type=threat_type,
                threat_status=threat_status,
            ),
        )

    async def _get_siem_data(
        self,
        endpoint: SIEMEndpoint,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch SIEM data from the specified endpoint in the given time period.

        Args:
            endpoint (SIEMEndpoint): The endpoint to query.
            start_time (datetime): The start time of the events.
            end_time (datetime): The end time of the events.
            response_format (str): The format in which data is returned. Default is JSON.
            threat_type (str): The threat type to return in the data. Default is None.
            threat_status (str): The threat status to return in the data. Default is None.

        Returns:
            SIEMResponse: The fetched events.

        """
        query_url = self._build_query(
            endpoint,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

        response = await self.get(query_url=query_url, response_model=SIEMResponse)
        return SIEMResponse.model_validate(response)

    async def fetch_clicks_blocked(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for clicks to malicious URLs blocked in the specified time period."""
        return await self._get_siem_data(
            SIEMEndpoint.CLICKS_BLOCKED,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

    async def fetch_clicks_permitted(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for clicks to malicious URLs permitted in the specified time period."""
        return await self._get_siem_data(
            SIEMEndpoint.CLICKS_PERMITTED,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

    async def fetch_messages_blocked(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for messages blocked in the specified time period which contained a known threat."""
        return await self._get_siem_data(
            SIEMEndpoint.MESSAGES_BLOCKED,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

    async def fetch_messages_delivered(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for messages delivered in the specified time period which contained a known threat."""
        return await self._get_siem_data(
            SIEMEndpoint.MESSAGES_DELIVERED,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

    async def fetch_issues(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for clicks to malicious URLs permitted and messages delivered containing a known threat within the specified time period."""
        return await self._get_siem_data(
            SIEMEndpoint.ISSUES,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )

    async def fetch_all(
        self,
        start_time: "datetime",
        end_time: "datetime",
        response_format: RESPONSE_FORMAT_REQUEST = "JSON",
        threat_type: THREAT_TYPE_REQUEST = None,
        threat_status: THREAT_STATUS_REQUEST = None,
    ) -> SIEMResponse:
        """Fetch events for all clicks and messages relating to known threats within the specified time period."""
        return await self._get_siem_data(
            SIEMEndpoint.ALL,
            start_time,
            end_time,
            response_format,
            threat_type,
            threat_status,
        )
