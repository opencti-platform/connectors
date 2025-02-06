# isort:skip_file
"""Define the Connector class for the ProofPoint TAP module integration with OpenCTI.
It handles the initialization, data retrieval, transformation to STIX format, and sending of data to OpenCTI.
"""

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pycti import (  # type: ignore[import-untyped] # pycti does not provide stubs
    OpenCTIConnectorHelper,
)

from proofpoint_tap.adapters.events import EventsAPIV2
from proofpoint_tap.domain.use_cases.ingest_incident import IncidentProcessor
from proofpoint_tap.domain.use_cases.ingest_report import ReportProcessor
from proofpoint_tap.errors import DataRetrievalError
from proofpoint_tap.ports.event import EventPort

if TYPE_CHECKING:
    from proofpoint_tap.ports.campaign import CampaignsPort
    from proofpoint_tap.ports.config import ConfigLoaderPort
    from proofpoint_tap.ports.event import EventsPort

CAMPAIGN_STATE_KEY = "last_campaign_datetime"
EVENT_STATE_KEY = "last_event_datetime"


class Connector:
    """Specifications of the external import connector.

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    """

    def __init__(
        self,
        config: "ConfigLoaderPort",
        campaigns: "CampaignsPort",
        events: "EventsPort",
        helper: OpenCTIConnectorHelper,
    ):
        """Initialize the Connector with necessary configurations."""
        # Load configuration file and connection helper
        self._config = config
        self._helper = helper
        self._logger = helper.connector_logger
        self._campaigns = campaigns
        self._events = events
        self._report_processor = ReportProcessor(
            tlp_marking_name=self._config.tap.marking_definition,
        )
        self._incident_processor = IncidentProcessor(
            tlp_marking_name=self._config.tap.marking_definition,
        )

        # To be intialized during work
        # keep track of current work
        self.work_id = None
        # keep track of current work datetime to update state
        # when finalizing work
        self._work_start_datetime: datetime | None = None
        # keep track of last datetime of campaign and event
        # for ingestion driving
        self._campaign_since_datetime: datetime | None = None
        self._event_since_datetime: datetime | None = None

    def _log_error(self, error_message: str) -> None:
        # to connector logger
        self._logger.error(message=error_message)
        # to OpenCTI
        self._helper.api.work.report_expectation(
            work_id=self.work_id, error={"error": error_message, "source": "CONNECTOR"}
        )

    def _force_get_state(self) -> dict[str, str]:
        self._helper.force_ping()
        return self._helper.get_state() or {}

    def _force_set_state(self, state: dict[str, str]) -> None:
        self._helper.set_state(state=state)
        self._helper.force_ping()

    def _force_update_state(self, key: str, value: "datetime") -> None:
        state = self._force_get_state()
        state[key] = value.isoformat()
        self._force_set_state(state)

    def _initiate_work(self) -> None:
        """Initiate a new work process in the OpenCTI platform.

        This method:
            1. Update data retrieval start date based on state
            2. Initiates work in OpenCTI platform and register work_id attribute
            3. Logs the event
            4. set the work ID for future use.
        """
        state = self._force_get_state()
        self._logger.debug("[CONNECTOR] Connector current state", {"state": state})

        def _set_acquisition_date(state_key: str) -> datetime:

            if state_key not in [CAMPAIGN_STATE_KEY, EVENT_STATE_KEY]:
                # check for the scatterbrained developer
                raise ValueError(f"Invalid state key: {state_key}")

            last_ingested_datetime_str = state.get(state_key)
            if last_ingested_datetime_str is not None:
                self._logger.info(
                    f"[CONNECTOR] Connector last ingested {state_key} datetime",
                    {state_key: last_ingested_datetime_str},
                )
                self._logger.warning(
                    "[CONNECTOR] Connector acquisition SINCE parameter overwritten",
                    {
                        "current": last_ingested_datetime_str,
                    },
                )
                return datetime.fromisoformat(last_ingested_datetime_str)

            self._logger.info(
                f"[CONNECTOR] Connector has never run successfully {state_key} ingestion..."
            )
            # Today at midnight UTC
            midnight = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            self._logger.info(
                f"[CONNECTOR] Connector {state_key} acquisition SINCE parameter set to",
                {"current": midnight.isoformat()},
            )
            return midnight

        if config.tap.export_campaigns:
            self._campaign_since_datetime = _set_acquisition_date(CAMPAIGN_STATE_KEY)

        if config.tap.export_events:
            self._event_since_datetime = _set_acquisition_date(EVENT_STATE_KEY)

        # Initiate a new work
        self.work_id = self._helper.api.work.initiate_work(
            self._helper.connect_id, self._helper.connect_name
        )
        self._work_start_datetime = datetime.now(timezone.utc)

        self._logger.info(
            "[CONNECTOR] Running connector...",
            {"connector_name": self._helper.connect_name},
        )

    def _finalize_work(self, error_flag: bool) -> None:
        """Finalize the work process in the OpenCTI platform.

        Args:
            error_flag(bool): Flag to indicate if the work process has an error.

        Returns:
            None

        """
        # Update State
        if config.tap.export_campaigns:
            self._force_update_state(
                key=CAMPAIGN_STATE_KEY,
                value=self._work_start_datetime,  # type: ignore[arg-type] # should not be None
            )
        if config.tap.export_events:
            self._force_update_state(
                key=EVENT_STATE_KEY,
                value=self._work_start_datetime,  # type: ignore[arg-type] # should not be None
            )

        self._helper.api.work.to_processed(
            work_id=self.work_id,
            message="Connector's work finished gracefully",
            in_error=error_flag,
        )

        # reset
        self.work_id = None
        self._work_start_datetime = None
        self._campaign_since_datetime = None
        self._event_since_datetime = None

    def _send_bundle(self, bundle_json: str) -> None:
        """Send the STIX bundle to the OpenCTI platform and update the total expectation.

        Args:
            bundle_json(str): The STIX bundle to send.

        Returns:
           None

        """
        bundles_sent = self._helper.send_stix2_bundle(
            bundle=bundle_json,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )
        self._logger.info(
            "STIX objects sent to OpenCTI.",
            {"bundles_sent": str(len(bundles_sent))},
        )

    def _process_campaigns(self) -> bool:
        """Fetch data, transform and send bundle. Return True if successful, False otherwise."""
        try:
            # Fetch data
            if self._campaign_since_datetime is None:
                # check for the scatterbrained developer
                raise ValueError(
                    "No start datetime to fetch campaigns, call _initiate_work first."
                )
            campaign_ids = self._campaigns.list(
                start_time=self._campaign_since_datetime,
                stop_time=datetime.now(timezone.utc),
            )
            self._logger.info(
                "[CONNECTOR] Campaigns IDs fetched",
                {"campaigns_count": len(campaign_ids)},
            )
            if len(campaign_ids) == 0:
                self._logger.info("No campaign IDs fetched.")
                return True

            # fetch details
            for campaign_id in campaign_ids:
                campaign_info = self._campaigns.details(campaign_id)
                self._logger.info(
                    "[CONNECTOR] Campaign details fetched",
                    {"campaign_id": campaign_id},
                )
                # process
                entities = self._report_processor.run_on(campaign_info)
                if len(entities) == 0:
                    self._logger.info("No entities to process.")
                    continue
                stix_objects = [entity.to_stix2_object() for entity in entities]
                # send
                self._send_bundle(self._helper.stix2_create_bundle(stix_objects))
                # update state
                last_ingested_campaign_start_time = campaign_info.start_datetime
                self._force_update_state(
                    key=CAMPAIGN_STATE_KEY, value=last_ingested_campaign_start_time
                )
            return True

        except DataRetrievalError as e:
            self._log_error(f"Data retrieval error: {str(e)}")
            return False

    def _process_events(self) -> bool:
        """Fetch data, transform and send bundle. Return True if successful, False otherwise."""
        try:
            # Fetch data
            if self._event_since_datetime is None:
                # check for the scatterbrained developer
                raise ValueError(
                    "No start datetime to fetch events, call _initiate_work first."
                )
            events: list[EventPort] = self._events.fetch(
                start_time=self._event_since_datetime,
                stop_time=datetime.now(timezone.utc),
                select=self._config.tap.events_type,
            )
            self._logger.info(
                "[CONNECTOR] Events fetched",
                {"events_count": len(events)},
            )
            if len(events) == 0:
                self._logger.info("No events fetched.")
                return True

            # process
            for event in events:
                entities = self._incident_processor.run_on_event(event=event)
                if len(entities) == 0:
                    self._logger.info("No entities to process.")
                    return True
                stix_objects = [entity.to_stix2_object() for entity in entities]
                # send
                self._send_bundle(self._helper.stix2_create_bundle(stix_objects))
                # update state
                last_ingested_event_start_time = max([event.time for event in events])
                self._force_update_state(
                    key=EVENT_STATE_KEY, value=last_ingested_event_start_time
                )
            return True

        except DataRetrievalError as e:
            self._log_error(f"Data retrieval error: {str(e)}")
            return False

    def work(self) -> None:
        """Define the main process of the connector."""
        error_flag = True
        try:
            self._logger.info(
                "[CONNECTOR] Starting connector work...",
                {"connector_name": self._helper.connect_name},
            )

            self._initiate_work()

            campaigns_error_flag = (
                not self._process_campaigns()
                if self._config.tap.export_campaigns
                else False
            )
            events_error_flag = (
                not self._process_events() if self._config.tap.export_events else False
            )

            error_flag = campaigns_error_flag or events_error_flag

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped by user"
            self._log_error(error_message)
            sys.exit(0)

        except Exception as err:
            error_flag = True
            self._logger.error("[CONNECTOR] Unexpected error.", {"error": str(err)})
            self._log_error("Unexpected error. See connector's log for more details.")

        finally:
            self._finalize_work(error_flag)

    def start(self) -> None:
        """Run the main process encapsulated in a scheduler.

        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self._helper.schedule_iso(
            message_callback=self.work,
            duration_period=self._config.connector.duration_period,
        )


if __name__ == "__main__":
    import traceback

    from proofpoint_tap.adapters.campaign import CampaignsAPIV2
    from proofpoint_tap.adapters.config import ConfigLoaderEnv

    # Configuration
    try:
        config = ConfigLoaderEnv()
        helper = OpenCTIConnectorHelper(config=config.to_dict(token_as_plaintext=True))
        campaigns = CampaignsAPIV2(
            base_url=config.tap.api_base_url,
            principal=config.tap.api_principal_key,
            secret=config.tap.api_secret_key,
            timeout=config.tap.api_timeout,
            retry=config.tap.api_retries,
            backoff=config.tap.api_backoff,
        )
        events = EventsAPIV2(
            base_url=config.tap.api_base_url,
            principal=config.tap.api_principal_key,
            secret=config.tap.api_secret_key,
            timeout=config.tap.api_timeout,
            retry=config.tap.api_retries,
            backoff=config.tap.api_backoff,
        )
    except (
        Exception
    ):  # Start up issue exception, Otherwise shoud be handle gracefully by the connector
        traceback.print_exc()
        sys.exit(1)

    # Run the connector
    # Error will be handled in the connector
    connector = Connector(config, campaigns, events, helper)
    connector.start()
