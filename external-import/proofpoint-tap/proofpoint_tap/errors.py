"""Offer python errors and tools."""


class DataRetrievalError(Exception):
    """Generic error for data retrieval."""


class ProofPointAPIRequestParamsError(Exception):
    """Proofpoint API error with request parameters."""


class ProofpointAPIError(DataRetrievalError):
    """Generic Proofpoint API error."""


class ProofpointAPI404Error(ProofpointAPIError):
    """Proofpoint API error with 400 status code."""


class ProofpointAPI404NoReasonError(ProofpointAPI404Error):
    """Proofpoint API error with 404 status code and no reason.

    Notes:
        * See client_api.v2.common.BaseClient._process_raw_response implementation for details.
        * See client_api.v2.campaign.CampaignClient.fetch_campaign implementation for technical decision log.

    """


class ProofpointAPI429Error(ProofpointAPIError):
    """Proofpoint API error with 429 status code.

    Used to handle rate limiting errors.
    """


class ProofpointAPIInvalidResponseError(ProofpointAPIError):
    """Proofpoint API error with an invalid response."""


class ConfigLoaderError(Exception):
    """Generic error for the config loader."""
