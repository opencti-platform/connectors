import sys
from datetime import datetime, timezone

import stix2
from pycti import OpenCTIConnectorHelper

from .client import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import SUPPORTED_COLLECTIONS


class ConnectorBambenek:
    """
    Represents Bambenek external import connector.
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

    def _collect_intelligence(self) -> list[stix2.v21._STIXBase21]:
        """
        Collect intelligence from Bambenek and convert into STIX object
        :param from_date: Minimum Bambenek IOC creation date timestamp
        :return: List of STIX objects
        """
        # validate collection configured
        for collection in self.config.bambenek_collections:
            if collection not in SUPPORTED_COLLECTIONS:
                self.helper.connector_logger.error(
                    f"Unsupported configured: {collection}"
                )
                self.config.bambenek_collections.remove(collection)

        self.helper.connector_logger.debug(
            f"Collections configured: {self.config.bambenek_collections}"
        )

        # init list and add the author in the stix bundle
        stix_objects = [self.converter_to_stix.author]

        for collection in self.config.bambenek_collections:
            self.helper.connector_logger.info(
                f"[CONNECTOR] to process collection: {collection}"
            )

            # Get entities from external sources
            entities = self.client.get_collections_entities(collection=collection)
            stix_objects.extend(
                self.converter_to_stix.convert_collection_to_stix(
                    collection=collection, entities=entities
                )
            )
        return stix_objects

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now_utc = datetime.now(timezone.utc)
            current_timestamp = int(datetime.timestamp(now_utc))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
                last_run = None

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = self.helper.connect_name

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            stix_objects = self._collect_intelligence()

            if stix_objects is not None and len(stix_objects) != 0:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle, work_id=work_id
                )

                self.helper.connector_logger.info(
                    "[CONNECTOR] Sending STIX objects to OpenCTI...",
                    {"bundles_sent": str(len(bundles_sent))},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now_utc.strftime("%Y-%m-%dT%H:%M:%S")

            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(current_state_datetime)
            )

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )

    @staticmethod
    def collection_transform_function(collection):
        pass
