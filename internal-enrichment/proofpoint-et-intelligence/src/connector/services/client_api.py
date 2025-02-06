from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from connector.services.config_variables import ProofpointEtIntelligenceConfig
from pycti import OpenCTIConnectorHelper
from tenacity import retry, stop_after_attempt, wait_exponential_jitter


class ProofpointEtIntelligenceClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ProofpointEtIntelligenceConfig
    ):
        """
        Initialize the Proofpoint ET Intelligence Client with necessary configurations
        Args:
            helper (OpenCTIConnectorHelper): An instance of the OpenCTI connector helper for logging and other utilities.
            config (ProofpointEtIntelligenceConfig): Configuration object containing API token and connector settings.
        Returns:
            None
        """
        self.helper = helper
        self.config = config
        self.headers = {"Authorization": f"{self.config.extra_api_key}"}

    def _build_url(
        self, entity_value: str, source_entity_type: str, target_entity_type: str | None
    ) -> str:
        """Method for building the url for the api request.

        Args:
            source_entity_type:
            entity_value:
            target_entity_type:

        Returns:

        """
        try:
            url = f"{self.config.extra_api_base_url}{source_entity_type}/{entity_value}"
            if target_entity_type:
                url += f"/{target_entity_type}"
            return url
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR-API] Error occurred while building the query request.",
                {"error": str(e)},
            )
            raise ValueError("Failed to build the query request due to an error.")

    @retry(
        stop=stop_after_attempt(max_attempt_number=1),
        wait=wait_exponential_jitter(initial=1, max=30, exp_base=2, jitter=1),
    )
    async def _fetch_data(
        self, entity_value: str, source_entity_type: str, target_entity_type: str = None
    ) -> dict:
        """
        Fetch intelligence data for a specific collection from the ProofPoint ET Intelligence API.
        This method sends an HTTP GET request to retrieve intelligence data for the specified entity.
        It handles various error scenarios, including retries, timeouts, and connection issues.
        Args:
            source_entity_type (str):
            target_entity_type (str):
        Returns:
            dict: The reputation data as a dictionary if the request is successful, or an error dictionary with
            details about the failure.
        """
        try:
            url_built = self._build_url(
                entity_value, source_entity_type, target_entity_type
            )
            async with ClientSession(
                headers=self.headers, raise_for_status=True
            ) as session:
                async with session.get(url=url_built) as response:
                    return await response.json()

        except ClientResponseError as err:
            raise ClientResponseError(
                status=err.status,
                request_info=err.request_info,
                history=err.history,
            )

        except ClientConnectionError as err:
            raise ClientConnectionError(str(err))

        except Exception as err:
            raise Exception(str(err))

    async def get_reputation(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve ip or domain reputation data from the ProofPoint ET Intelligence API.
        Args:
            entity_value (str):
            source_entity_type (str): The identifier of the domain reputation list to query.
        Returns:
            dict: The domain reputation data as a dictionary, or an error dictionary if the request fails.
        """
        return await self._fetch_data(entity_value, source_entity_type, "reputation")

    async def get_ips(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve ips data from the ProofPoint ET Intelligence API.

        Args:
            entity_value:
            source_entity_type:

        Returns:

        """

        response = await self._fetch_data(entity_value, source_entity_type, "ips")
        return response

    async def get_domains(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve domains data from the ProofPoint ET Intelligence API.

        Args:
            entity_value (str):
            source_entity_type (str): The source entity type for which intelligence data is requested

        Returns:

        """
        return await self._fetch_data(entity_value, source_entity_type, "domains")

    async def get_malwares(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve files data from the ProofPoint ET Intelligence API.

        Args:
            entity_value (str):
            source_entity_type (str): The source entity type for which intelligence data is requested

        Returns:

        """
        return await self._fetch_data(entity_value, source_entity_type, "samples")

    async def get_geolocation(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve geolocation data from the ProofPoint ET Intelligence API.

        Args:
            entity_value (str):
            source_entity_type (str): The source entity type for which intelligence data is requested

        Returns:

        """
        return await self._fetch_data(entity_value, source_entity_type, "geoloc")

    async def get_asn(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve anonymous system data from the ProofPoint ET Intelligence API.

        Args:
            entity_value (str):
            source_entity_type (str): The source entity type for which intelligence data is requested

        Returns:

        """
        return await self._fetch_data(entity_value, source_entity_type, "asn")

    async def get_details(self, entity_value: str, source_entity_type: str) -> dict:
        """Retrieve file details data from the ProofPoint ET Intelligence API.

        Args:
            entity_value (str):
            source_entity_type: source_entity_type (str): The source entity type for which intelligence data is requested

        Returns:

        """
        return await self._fetch_data(entity_value, source_entity_type)
