import sys
from datetime import datetime

import stix2
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .utils import find_matching_file_ids, format_incident, validate_incident


class SentinelIncidentsConnector:
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
        self.client = ConnectorClient(self.helper, self.config)
        self.tlp_marking = stix2.TLP_RED
        self.converter_to_stix = ConverterToStix(
            self.helper, self.config, self.tlp_marking
        )

    def _get_last_incident_date(self) -> int:
        """
        Get last incident timestamp from connector's state.
        :return: Connector's state last incident timestamp
        """
        state = self.helper.get_state()
        if state and "last_incident_timestamp" in state:
            last_timestamp = state["last_incident_timestamp"]
            return last_timestamp

        if self.config.import_start_date:
            datetime_obj = datetime.fromisoformat(self.config.import_start_date)
            last_timestamp = int(round(datetime_obj.timestamp()))
            return last_timestamp

    def _set_last_incident_date(self, incident_timestamp: int):
        """
        Set last incident timestamp to connector's state.'
        :param incident_timestamp: Last incident timestamp
        """
        state = self.helper.get_state()
        if state is not None:
            state["last_incident_timestamp"] = incident_timestamp
            self.helper.set_state(state)
        else:
            self.helper.set_state({"last_incident_timestamp": incident_timestamp})

    def _extract_intelligence(self, incident: dict) -> list[object]:
        """
        Extract intelligence from incident and convert it to STIX 2.1 objects.
        :param incident: Incident to extract intelligence from
        :return: STIX 2.1 objects.
        """
        stix_objects = []

        for alert in incident.get("alerts", []):
            # Create Stix Incident
            stix_incident = self.converter_to_stix.create_incident(alert)
            stix_objects.append(stix_incident)

            for technique in alert.get("mitreTechniques", []):
                # Create Stix AttackPattern
                stix_attack_pattern = (
                    self.converter_to_stix.create_mitre_attack_pattern(technique)
                )
                if stix_attack_pattern:
                    stix_objects.append(stix_attack_pattern)
                    stix_relationship_attack_pattern = (
                        self.converter_to_stix.create_relationship(
                            source_id=stix_incident.id,
                            target_id=stix_attack_pattern.id,
                            relationship_type="uses",
                        )
                    )
                    stix_objects.append(stix_relationship_attack_pattern)

            # This mapping is used for the priority of evidences because ‘processEvidence’ often includes information
            # from ‘fileEvidence’ and ‘fileEvidence’ usually includes information from ‘fileHashEvidence’.
            priority_evidence_files = {
                "#microsoft.graph.security.processEvidence": 1,
                "#microsoft.graph.security.fileEvidence": 2,
                "#microsoft.graph.security.fileHashEvidence": 3,
            }
            list_evidence = alert.get("evidence", [])
            list_evidence_sorted = sorted(
                list_evidence,
                key=lambda x: priority_evidence_files.get(
                    x.get("@odata.type"), float("inf")
                ),
            )

            # Clear the set of all hashes for each incident (alerts)
            self.converter_to_stix.all_hashes.clear()

            for evidence in list_evidence_sorted:
                evidence_type = evidence.get("@odata.type", [])
                match evidence_type:
                    # userEvidence
                    case "#microsoft.graph.security.userEvidence":
                        # Create Stix UserAccount
                        stix_account = (
                            self.converter_to_stix.create_evidence_user_account(
                                evidence
                            )
                        )
                        if stix_account:
                            stix_objects.append(stix_account)
                            stix_relationship_account = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_account.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_account)

                    # ipEvidence
                    case "#microsoft.graph.security.ipEvidence":
                        # Create Stix IPv4Address
                        stix_ip = self.converter_to_stix.create_evidence_ipv4(evidence)
                        if stix_ip:
                            stix_objects.append(stix_ip)
                            stix_relationship_ip = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_ip.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_ip)

                    # urlEvidence
                    case "#microsoft.graph.security.urlEvidence":
                        # Create Stix Url
                        stix_url = self.converter_to_stix.create_evidence_url(evidence)
                        if stix_url:
                            stix_objects.append(stix_url)
                            stix_relationship_url = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_url.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_url)

                    # deviceEvidence
                    case "#microsoft.graph.security.deviceEvidence":
                        # Create CustomObservableHostname
                        stix_hostname = self.converter_to_stix.create_evidence_custom_observable_hostname(
                            evidence
                        )
                        if stix_hostname:
                            stix_objects.append(stix_hostname)
                            stix_relationship_hostname = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_hostname.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_hostname)

                    # processEvidence, fileEvidence and fileHashEvidence
                    case evidence_file if (
                        evidence_file in priority_evidence_files.keys()
                    ):
                        file = (
                            evidence.get("imageFile")
                            or evidence.get("fileDetails")
                            or evidence.get("value")
                        )
                        # Create Stix Directory
                        stix_directory = (
                            self.converter_to_stix.create_evidence_directory(file)
                            if isinstance(file, dict)
                            else None
                        )
                        # Create Stix File
                        stix_file = self.converter_to_stix.create_evidence_file(
                            evidence, stix_directory
                        )
                        if stix_file:
                            # Add Stix File in stix_objects and relationship with incident
                            stix_objects.append(stix_file)
                            stix_relationship_file = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_file.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_file)
                        if stix_directory and stix_file:
                            # Add Stix Directory in stix_objects and relationship with incident
                            stix_objects.append(stix_directory)
                            stix_relationship_directory = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_directory.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_directory)
                        else:
                            self.helper.connector_logger.debug(
                                "The creation of the stix file will be ignored as it already exists "
                                "or no hashes are available.",
                                {"evidence": evidence_file, "hashes": file},
                            )

                    # malwareEvidence
                    case "#microsoft.graph.security.malwareEvidence":
                        # Matching malware to files by name
                        files = evidence.get("files")
                        list_files_names = []
                        stix_files_objects = []
                        if files and len(files) != 0:
                            for file in files:
                                file_details = file.get("fileDetails")
                                if file_details:
                                    list_files_names.append(
                                        file_details.get("fileName")
                                    )
                                    stix_files_objects = find_matching_file_ids(
                                        file_details.get("fileName"), stix_objects
                                    )

                        # Create stix Malware
                        stix_malware = self.converter_to_stix.create_evidence_malware(
                            evidence, stix_files_objects
                        )
                        if stix_malware:
                            stix_objects.append(stix_malware)
                            stix_relationship_malware = (
                                self.converter_to_stix.create_relationship(
                                    source_id=stix_malware.id,
                                    target_id=stix_incident.id,
                                    relationship_type="related-to",
                                )
                            )
                            stix_objects.append(stix_relationship_malware)

        stix_case = self.converter_to_stix.create_custom_case_incident(
            incident, stix_objects
        )
        stix_objects.append(stix_case)

        return stix_objects

    def process_message(self):
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            last_incident_timestamp = self._get_last_incident_date()
            if last_incident_timestamp:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last imported incident timestamp:",
                    {"last_incident_timestamp": last_incident_timestamp},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # A token is valid for 1 hour so we get a fresh one on every run
            self.client.set_oauth_token()

            stix_objects = []

            incidents = self.client.get_incidents(last_incident_timestamp)
            # Incidents are listed from oldest to most recent.
            for incident in reversed(incidents):
                incident = format_incident(incident)
                if validate_incident(incident, last_incident_timestamp):
                    incident_stix_objects = self._extract_intelligence(incident)
                    stix_objects.extend(incident_stix_objects)

                    last_incident_timestamp = incident["lastUpdateDateTime"]

            if stix_objects:
                # Add author and default TLP marking for consistent bundle
                stix_objects.append(self.converter_to_stix.author)
                stix_objects.append(self.tlp_marking)

                stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    stix_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self._set_last_incident_date(last_incident_timestamp)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_incident_timestamp as "
                + str(last_incident_timestamp)
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
