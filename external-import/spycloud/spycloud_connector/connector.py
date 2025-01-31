import sys
from datetime import datetime
from typing import TYPE_CHECKING

from pycti import OpenCTIConnectorHelper
from spycloud_connector.models.opencti import OCTIBaseModel
from spycloud_connector.services import ConfigLoader, ConverterToStix, SpycloudClient
from spycloud_connector.utils.helpers import dict_to_serialized_list

if TYPE_CHECKING:
    from spycloud_connector.models.spycloud import (
        BreachRecordSeverity,
        BreachRecordWatchlistType,
    )


class SpyCloudConnector:
    """
    Main class of Spycloud connector orchestrating steps to collect, prepare and send data to OpenCTI.
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(self.config.to_dict())
        self.client = SpycloudClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

        self.current_state = None

    def _get_last_import_date(
        self, watchlist_type: "BreachRecordWatchlistType" = None
    ) -> datetime:
        """
        Get last import datetime from connector's current state.
        It does *not* ping OpenCTI, use self.helper.get_state() to get connector's state from OpenCTI.
        :param watchlist_type: Optional watchlist_type filter. If not provided, `last_import_date` is returned.
        :return: Last import datetime or default `import_start_date` from connector's config.
        """
        last_import_date = None

        last_import_iso_key = (
            f"{watchlist_type}_last_import_date"
            if watchlist_type
            else "last_import_date"
        )
        last_import_iso = self.current_state.get(last_import_iso_key)
        if last_import_iso:
            last_import_date = datetime.fromisoformat(last_import_iso)

        return last_import_date or self.config.spycloud.import_start_date

    def _set_last_import_date(
        self,
        last_import_date: datetime = None,
        watchlist_type: "BreachRecordWatchlistType" = None,
    ) -> None:
        """
        Set last import datetime in connector's current state.
        It does *not* ping OpenCTI, use self.helper.set_state() to force update connector's state on OpenCTI.
        :param last_import_date: Last import datetime to store
        :param watchlist_type: Optional watchlist_type filter. If not provided, `last_import_date` is set.
        """
        last_import_iso_key = (
            f"{watchlist_type}_last_import_date"
            if watchlist_type
            else "last_import_date"
        )
        self.current_state[last_import_iso_key] = last_import_date.isoformat()

    def _collect_intelligence(
        self,
        watchlist_type: "BreachRecordWatchlistType" = None,
        severity_levels: "BreachRecordSeverity" = None,
        since: datetime = None,
    ) -> list[OCTIBaseModel]:
        """
        Collect intelligence from Spycloud and convert data into OCTI objects.
        :return: List of OCTI objects
        """
        octi_objects = []

        breach_records = self.client.get_breach_records(
            watchlist_type=watchlist_type,
            severity_levels=severity_levels,
            since=since,
        )
        for breach_record in breach_records:
            breach_catalog = self.client.get_breach_catalog(breach_record.source_id)

            octi_indicent = self.converter_to_stix.create_incident(
                breach_record=breach_record,
                breach_catalog=breach_catalog,
            )
            octi_objects.append(octi_indicent)

            octi_observables = self.converter_to_stix.create_observables(
                breach_record=breach_record
            )
            octi_objects.extend(octi_observables)

            for octi_observable in octi_observables:
                relationship = self.converter_to_stix.create_related_to_relationship(
                    source=octi_observable,
                    target=octi_indicent,
                )
                octi_objects.append(relationship)

        return octi_objects

    def _send_stix_bundle(
        self, work_id: str, octi_objects: list[OCTIBaseModel]
    ) -> list:
        """
        Create a consistent STIX bundle from OCTI objects and send it to the worker.
        :return: List of sent STIX bundles
        """
        if not octi_objects:
            return []

        # Ensure consistent bundle
        octi_objects.append(self.converter_to_stix.author)
        octi_objects.append(self.converter_to_stix.tlp_marking)

        stix_objects = [octi_object.to_stix2_object() for octi_object in octi_objects]

        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=stix_bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

        return bundles_sent

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence.
        """
        logger = self.helper.connector_logger

        try:
            logger.info(
                "[CONNECTOR] Starting connector...",
                {"connector_name": self.helper.connect_name},
            )

            self.current_state = self.helper.get_state() or {}
            if self.current_state:
                logger.info("[CONNECTOR] Connector current state: ", self.current_state)
            else:
                logger.info(
                    "[CONNECTOR] Connector has never run",
                    {"import_start_date": self.config.spycloud.import_start_date},
                )

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )

            logger.info("[CONNECTOR] Gathering data...")

            # If no specific watchlist type is set, pass None to ignore watchlist_type filter
            watchlist_types_args = self.config.spycloud.watchlist_types or [None]
            for watchlist_type_arg in watchlist_types_args:
                last_import_date = self._get_last_import_date(
                    watchlist_type=watchlist_type_arg
                )

                octi_objects = self._collect_intelligence(
                    watchlist_type=watchlist_type_arg,
                    severity_levels=self.config.spycloud.severity_levels,
                    since=last_import_date or self.config.spycloud.import_start_date,
                )
                if octi_objects:
                    bundles_sent = self._send_stix_bundle(work_id, octi_objects)
                    logger.info(
                        "Sending STIX objects to OpenCTI...",
                        {"bundles_sent": len(bundles_sent)},
                    )

                    self._set_last_import_date(
                        last_import_date=octi_objects[0].created_at,
                        watchlist_type=watchlist_type_arg,
                    )

            logger.debug("Updating connector's state", self.current_state)
            self.helper.set_state(self.current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"updating connector's state with {dict_to_serialized_list(self.current_state)}"
            )
            self.helper.api.work.to_processed(work_id, message)
            logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler.
        It allows you to schedule the process to run at a certain intervals.
        This specific scheduler from the pycti connector helper will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB).
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
