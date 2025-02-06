import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .s1_client import ConnectorClient


class IncidentConnector:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.s1_client = ConnectorClient(self.helper, self.config)
        self.stix_client = ConverterToStix(self.helper)

        self.cache = []
        self.to_process = []

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
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
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

            friendly_name = "SentinelOne Incident Connector"

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            self.query_new_incidents()

            if self.to_process is not None and len(self.to_process) != 0:
                self.process_incidents(work_id)
                ##complete

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
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

    def query_new_incidents(self):
        def is_applicable(incident_id):
            incident_notes = self.s1_client.retreive_incident_notes(incident_id)
            if incident_notes:
                for note in incident_notes:
                    if self.config.sign in note.get("text", ""):
                        return True
            else:
                return None
            return False

        self.helper.log_info("Retrieving and filtering Incidents...")
        present_incidents = self.s1_client.fetch_incidents()

        if present_incidents is None:
            self.helper.log_info("Unable to retrieve Incidents from SentinelOne")
        elif present_incidents is False:
            self.helper.log_info("No Incidents were found from SentinelOne")
        else:

            uncached_incidents = [
                inc
                for inc in present_incidents
                if inc not in self.cache and inc not in self.to_process
            ]
            for incident in uncached_incidents:
                applicability = is_applicable(incident)
                if applicability:
                    self.to_process.append(incident)
                    self.helper.log_info(
                        f"Found applicable incident with ID: {incident}"
                    )
                elif applicability is None:
                    self.helper.log_debug(
                        "Unable to determine applicability due to a SentinelOne API error"
                    )
                else:
                    # self.cache.append(incident)
                    self.helper.log_debug(
                        f"Sign not found in notes, incident not applicable with ID: {incident}"
                    )

        self.helper.log_info("Retrieval process complete")

    def process_incidents(self, work_id):
        self.helper.log_info(
            f"Beginning creation for {len(self.to_process)} applicable Incidents"
        )

        for i, s1_incident_id in enumerate(self.to_process):
            self.helper.log_info(f"Creating Incident for S1 ID: {s1_incident_id}")

            # required steps
            s1_incident = self.s1_client.retreive_incident(s1_incident_id)
            if not s1_incident:
                self.helper.log_info(
                    "Unable to retrieve the Incident from SentinelOne, halting process."
                )
                return False
            self.helper.log_info("Retrieved Incident from SentinelOne.")

            incident_items = []
            incident_and_source = self.stix_client.create_incident(
                s1_incident, s1_incident_id, self.config.s1_url
            )
            if not incident_and_source:
                self.helper.log_info(
                    "Unable to create corresponding Incident in Stix form, halting process."
                )
                return False
            self.helper.log_info("Created Corresponding Stix Incident.")
            incident_items = incident_items + incident_and_source

            # optional steps
            incident = incident_and_source[0]

            endpoint_and_relationship = self.stix_client.create_endpoint_observable(
                s1_incident, incident["id"]
            )
            if not endpoint_and_relationship:
                self.helper.log_info("No Endpoint Observable created, continuing.")
            else:
                self.helper.log_info(
                    "Created Corresponding Endpoint Observable for the affected Endpoint."
                )
                incident_items = incident_items + endpoint_and_relationship

            attack_patterns = self.stix_client.create_attack_patterns(
                s1_incident, incident["id"]
            )
            if not attack_patterns:
                self.helper.log_info("No Attack Patterns created, continuing.")
            else:
                self.helper.log_info("Created Corresponding Stix Attack Patterns.")
                incident_items = incident_items + attack_patterns

            s1_notes = self.s1_client.retreive_incident_notes(s1_incident_id)
            if s1_notes:
                notes = self.stix_client.create_notes(s1_notes, incident["id"])
                if not notes:
                    self.helper.log_info("No Notes created, continuing.")
                self.helper.log_info("Created Corresponding Stix Notes.")
                incident_items = incident_items + notes
            else:
                self.helper.log_info(
                    "Unable to retrieve Notes from SentinelOne, no Notes created, continuing."
                )

            indicators = self.stix_client.create_hash_indicators(
                s1_incident, incident["id"]
            )
            if not indicators:
                self.helper.log_info("No Indicators created, continuing.")
            else:
                self.helper.log_info("Created Corresponding Stix Indicators.")
                incident_items = incident_items + indicators

            bundle = self.helper.stix2_create_bundle(incident_items)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                "Sending STIX objects to OpenCTI...",
                {"bundles_sent": {str(len(bundles_sent))}},
            )

            self.helper.log_info(
                f"Incident Creation Completed for S1 ID: {s1_incident_id}."
            )
            self.cache.append(s1_incident_id)

        self.to_process = [inc for inc in self.to_process if inc not in self.cache]
        self.helper.log_info("Completed Incident Creation Process.")

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
