import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .connector_client import ConnectorClient
from .converter_to_stix import ConverterToStix
from .sources.data_source import DataSource


class ConnectorVulnCheck:
    """
    Connector class for VulnCheck

    This class wraps the entire process of collectioning intelligence from the
    VulnCheck API and converting it into STIX objects.

    Attributes:
    - config: Configuration object
    - helper: OpenCTIConnectorHelper object
    - client: ConnectorClient object
    - converter_to_stix: ConverterToStix object
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

    def _collect_intelligence(
        self, target_data_sources: list[DataSource], config_state
    ) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []
        target_data_sources = self._get_target_data_sources()

        # Make sure the author exists!
        stix_objects.append(self.converter_to_stix.author)

        for source in target_data_sources:
            self.helper.log_info(
                f"[CONNECTOR] Collecting data for {source.name}",
            )
            # Get entities from source
            new_stix_objects = source.collect_data_source(self, config_state)
            stix_objects.extend(new_stix_objects)

        return stix_objects

    def _get_target_data_sources(self) -> list[DataSource]:
        entitled_data_sources = self.client.get_entitled_sources()
        self.helper.connector_logger.debug(
            "[CONNECTOR] Entitled Data Sources",
            {"data_sources": entitled_data_sources},
        )
        configured_data_sources = self.config.get_configured_sources()
        self.helper.connector_logger.debug(
            "[CONNECTOR] Configured Data Sources",
            {"data_sources": configured_data_sources},
        )
        target_data_source_strings = self._get_intersection_of_string_lists(
            entitled_data_sources, configured_data_sources
        )

        target_data_sources: list[DataSource] = []

        for name in target_data_source_strings:
            target_data_sources.append(DataSource.from_string(name))
        self.helper.connector_logger.debug(
            "[CONNECTOR] Target Data Sources", {"data_sources": target_data_sources}
        )
        return target_data_sources

    def _get_intersection_of_string_lists(
        self, a: list[str], b: list[str]
    ) -> list[str]:
        return list(set(a) & set(b))

    def _get_time_until_next_run(self, current_timestamp: int, last_run_timestamp: int):
        time_diff = current_timestamp - last_run_timestamp
        if time_diff < 24 * 3600:
            remaining_time = 24 * 3600 - time_diff
            hours, remainder = divmod(remaining_time, 3600)
            minutes, _ = divmod(remainder, 60)
            return hours, minutes
        return None, None

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        work_id = ""

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            # Get the target data sources for this run
            target_data_sources = self._get_target_data_sources()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                last_run_dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
                last_run_timestamp = int(last_run_dt.timestamp())

                hours, minutes = self._get_time_until_next_run(
                    current_timestamp, last_run_timestamp
                )
                if hours is not None and minutes is not None:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Last data ingest less than 24 hours ago, next ingest in {hours}h{minutes}m",
                    )
                    return

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            try:
                # Initiate new work
                friendly_name = "VulnCheck run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                self.helper.connector_logger.info(
                    "[CONNECTOR] Running connector...",
                    {"connector_name": self.helper.connect_name},
                )

                stix_objects = self._collect_intelligence(
                    target_data_sources, current_state
                )

                if stix_objects is not None and len(stix_objects) != 0:
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] Bundling objects",
                    )
                    stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Preparing to send bundle",
                    )
                    bundles_sent = self.helper.send_stix2_bundle(
                        stix_objects_bundle, work_id=work_id
                    )
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Sending STIX objects to OpenCTI...",
                        {"bundles_sent": {str(len(bundles_sent))}},
                    )

            except Exception as e:
                self.helper.log_error(str(e))

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "[CONNECTOR] Updating connector state for collected data sources",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            new_state = self.get_updated_state(
                target_data_sources, current_state_datetime
            )

            self.helper.set_state(new_state)

            message = (
                f"[CONNECTOR] {self.helper.connect_name} connector successfully ran, storing last_run as "
                + str(last_run_datetime)
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

    def get_updated_state(
        self, target_data_sources: list[DataSource], current_state_datetime
    ) -> dict:
        new_state = {
            data_source.name: current_state_datetime
            for data_source in target_data_sources
        }
        new_state["last_run"] = current_state_datetime
        return new_state

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
            duration_period=str(self.config.duration_period),
        )
