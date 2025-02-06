# Client API

The Proofpoint TAP Client API is a RESTful API that allows you to interact with the Proofpoint Targeted Attack Protection (TAP) product. The API provides a set of endpoints that allow you to interact with the TAP product programmatically.

For now, only the `v2` version of the API is supported.


## Getting Started

To get started with the Proofpoint TAP Client API, you will need your API credentials ('principal' and 'secret') and the base URL for the API.

## Proofpoint TAP API documentation

https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation [consulted on January 13th, 2025]

## Architecture

### Clients

Each API endpoint is represented by a class in the `proofpoint_tap.client_api.v2` module. Each class has methods that correspond to the HTTP methods that are supported by the endpoint. For example, the `Campaigns` endpoint has a `fetch_campaigns` method that corresponds to the `GET /v2/campaigns/ids` endpoint.

### Response Models

Each module propose 'ResponseModel' classes that represent the response of the API. These classes are used to parse the response of the API and provide a more structured way to access the data. For example, the `CampaignIdsResponse` class is used to parse the response of the `GET /v2/campaigns/ids` endpoint.

This classes perfoms a run time validation of the response data, and are mainly permissive, emitting warning messages when the response data does not match the expected format rather than raising validation errors.

## Basic Usage

```python
import asyncio
from datetime import datetime, timedelta, timezone

from yarl import URL

from proofpoint_tap.client_api.v2 import CampaignClient

client = CampaignClient(
    base_url=URL("https://tap-api-v2.proofpoint.com"),
    principal="changeme",
    secret="changeme",
    timeout=timedelta(seconds=30),
    retry=3,
    backoff=timedelta(seconds=5),
)

start_time = datetime(2023, 12, 13, tzinfo=timezone.utc)
end_time = datetime(2023, 12, 13, 12, 00, 00, tzinfo=timezone.utc)

ids_response = asyncio.run(
    client.fetch_campaign_ids(
        start_time, end_time
    )
)
```

## Available Public Classes

From the `proofpoint_tap.client_api.v2` module:

- `CampaignClient`
- `ForensicsClient`
- `ThreatClient`
- `SIEMClient`


## Exceptions

The `proofpoint_tap.client_api` items use the `proofpoint_tap.errors` module to define exceptions that are raised when an error occurs. The exceptions are:

- `ProofpointAPIError`: Base class for all exceptions.
- `ProofPointAPIRequestParamsError`: Raised when the request parameters are invalid before trying to request the API.
- `ProofpointAPI404Error`: Raised when the API returns a 404 status code.
- `ProofpointAPI404NoReasonError`: Raised when the API returns a 404 status code without a reason. (see `proofpoint_tap.client_api.v2.CampaignClient.fetch_campaign_ids` method docstring for more information)
- `ProofpointAPI429Error`: Raised when the API returns a 429 status code.
- `ProofpointAPIInvalidResponseError`: Raised when the API returns an invalid response.

## Danger Zone

The API is rate-limited. Be careful with the number of requests you make.

Due to quota limitation, a decorator to use a local cache using pickle files has been implemented to store the responses of the API. This cache is for development purpose only. See the `proofpoint_tap.client_api.tools.cache_get_response_decorator` mehod docstring for more information.
