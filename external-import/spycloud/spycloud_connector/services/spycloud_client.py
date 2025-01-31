from datetime import datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Generator
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter, Retry
from spycloud_connector.models.spycloud import BreachCatalog, BreachRecord
from spycloud_connector.services import ConfigLoader

if TYPE_CHECKING:
    from spycloud_connector.models.spycloud import (
        BreachRecordSeverity,
        BreachRecordWatchlistType,
    )


class SpycloudClient:
    """
    Provides methods to request data from SpyCloud API.
    """

    def __init__(
        self, helper: OpenCTIConnectorHelper = None, config: ConfigLoader = None
    ):
        """
        Initialize the client with necessary configurations.
        Spycloud API documentation: https://spycloud-external.readme.io/sc-enterprise-api/docs/getting-started
        :param helper: OpenCTIConnectorHelper instance
        :param config: ConfigLoader instance
        """
        self.helper = helper
        self.config = config

        self.session = self._session(
            headers={
                "Accept": "application/json",
                "X-API-KEY": self.config.spycloud.api_key,
            }
        )

    def _session(self, headers: dict = None) -> requests.Session:
        """
        Internal method to create a session with retriable requests.
        :param headers: Global headers to attach to session's requests.
        :return: Session with headers and retry strategy.
        """
        session = requests.Session()
        if headers:
            session.headers.update(headers)

        retry_strategy = Retry(
            total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount(self.config.spycloud.api_base_url, adapter)

        return session

    def _request(self, method: str = "GET", url: str = None, **kwargs) -> dict | None:
        """
        Internal method to handle API requests.
        :param kwargs: Any arguments accepted by request.request()
        :return: Parsed response body
        """
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint", {"url": url}
            )

            return response.json() if response.content else None

        except requests.exceptions.RetryError as err:
            self.helper.connector_logger.error(
                f"[API] Maximum retries exceeded while sending {method.upper()} request: ",
                {"url": url, "error": err},
            )

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                f"[API] Error while sending {method.upper()} request: ",
                {"url": url, "error": err},
            )

    # Use cache to avoid requesting to the API the same breach catalog over and over.
    # Cache is never cleared manually as we don't need fresh breach catalogs data (only their title are used).
    # Default maxsize used (128 entries).
    @lru_cache
    def get_breach_catalog(self, breach_catalog_id: int) -> BreachCatalog | None:
        """
        Retrieve a breach catalog from Spycloud.
        :param breach_catalog_id: ID of breach catalog to retrieve
        :return: Found breach catalog
        """
        url = urljoin(
            self.config.spycloud.api_base_url, f"breach/catalog/{breach_catalog_id}"
        )

        data = self._request(method="GET", url=url)
        if not data:
            return None

        results = data["results"]
        if not results:
            return None

        result = results[0]

        return BreachCatalog(**result)

    def get_breach_records(
        self,
        watchlist_type: "BreachRecordWatchlistType" = None,
        severity_levels: list["BreachRecordSeverity"] = None,
        since: datetime = None,
    ) -> Generator[BreachRecord, None, None]:
        """
        Retrieve breach records from Spycloud.
        :param watchlist_type: Optional query param to filter breach records by watchlist type
        :param severity_levels: Optional query param to filter breach records by severity levels
        :param since: Optional query param to filter breach records by publish date
        :return: List of breach records
        """
        url = urljoin(self.config.spycloud.api_base_url, "breach/data/watchlist")
        params = {
            "watchlist_type": watchlist_type if watchlist_type else None,
            "severity": severity_levels if severity_levels else None,
            "since": since.strftime("%Y-%m-%d") if since else None,
        }

        cursor = True  # only to enter while loop
        while cursor:
            data = self._request(method="GET", url=url, params=params)

            results = data["results"] if data else []
            for result in results:
                yield BreachRecord(**result)

            cursor = data["cursor"] if data else None
            if cursor:
                params["cursor"] = cursor
