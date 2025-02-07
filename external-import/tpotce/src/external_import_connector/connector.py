import sys
from datetime import datetime, timezone
from pycti import OpenCTIConnectorHelper

import pandas as pd
import stix2
import urllib3

from .converter_to_stix import ConverterToStix
from .elasticsearch_manager import ElasticsearchManager
from .external_import import ExternalImportConnector
from .config_variables import ConfigConnector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helpe
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        # Default marking level
        self.default_marking = stix2.TLP_GREEN
        self.tlp_marking = self.get_tlp_marking(self.config.config_marking)

        # Initialize helper components
        self.converter_to_stix = ConverterToStix(
            self.helper,
            self.tlp_marking,
            self.config.stix_author,
            self.config.stix_labels,
            self.config.download_payloads,
            proxy_url=self.config.proxy_url,
        )
        self.helper.connector_logger.debug("ConverterToStix initialized.")
        self.elasticsearch_manager = ElasticsearchManager(
            self.config.elasticsearch_host,
            self.config.username,
            self.config.password,
            self.helper,
        )

        self.helper.connector_logger.debug("ElasticsearchManager initialized.")

        if self.config.retrofeed_start_date:
            try:
                self.config.retrofeed_start_date = datetime.fromisoformat(
                    self.config.retrofeed_start_date.replace("Z", "+00:00")
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                self.helper.connector_logger.error(
                    f"Invalid format for TPOTCE2OCTI_RETROFEED_START_DATE: {self.config.retrofeed_start_date}. Disabling retrofeed."
                )
                self.config.retrofeed_start_date = None

    def _collect_intelligence(self, last_run, now):
        self.helper.connector_logger.info(
            f"Collecting intelligence from {str(last_run)} to {str(now)}..."
        )
        hits = self.elasticsearch_manager.query_with_pagination(last_run, now)

        stix_objects = []

        if hits:
            self.helper.connector_logger.debug(
                "Creating DataFrame from Elasticsearch hits."
            )
            df = pd.DataFrame([hit["_source"] for hit in hits])
            self.helper.connector_logger.debug(f"Elasticsearch DataFrame:\n{df}")

            if "src_ip" not in df.columns:
                self.helper.connector_logger.warning(
                    "No 'src_ip' column found in the DataFrame."
                )

            self.helper.connector_logger.debug("Exporting DataFrame to STIX format.")
            stix_objects = self.converter_to_stix.export_to_stix(df)

            self.helper.connector_logger.debug(
                "Updating connector state with the latest run time."
            )
            self.helper.set_state({"last_run": now.isoformat()})
        else:
            self.helper.connector_logger.info("No hits found in Elasticsearch query.")

        return stix_objects

    def get_tlp_marking(self, config_marking):
        """
        Set the corresponding TLP marking based on configuration.
        """
        return {
            "tlp:clear": stix2.TLP_WHITE,
            "tlp:white": stix2.TLP_WHITE,
            "tlp:green": stix2.TLP_GREEN,
            "tlp:amber": stix2.TLP_AMBER,
            "tlp:red": stix2.TLP_RED,
        }.get(
            config_marking.lower(), stix2.TLP_GREEN
        )  # Default to TLP_GREEN

    def process_message(self):
        """
        Connector main process to collect intelligence
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )

                # Parse `last_run` based on its type
                if isinstance(last_run, str):  # ISO 8601 string
                    try:
                        last_run = datetime.fromisoformat(
                            last_run.replace("Z", "+00:00")
                        )
                    except ValueError:
                        self.helper.connector_logger.error(
                            f"Invalid ISO format for last_run: {last_run}. Defaulting to now."
                        )
                        last_run = now
                elif isinstance(last_run, (int, float)):  # Unix timestamp
                    last_run = datetime.fromtimestamp(last_run, tz=timezone.utc)
                else:
                    self.helper.connector_logger.error(
                        "Invalid last_run value. Defaulting to now."
                    )
                    last_run = now
            else:
                # First run: use retrofeed_start_date if available
                if self.config.retrofeed_start_date:

                    last_run = self.config.retrofeed_start_date
                    self.helper.connector_logger.info(
                        f"First run: Using retrofeed start date as last_run: {last_run.isoformat()}Z"
                    )
                else:
                    last_run = now
                    self.helper.connector_logger.info(
                        "First run: No retrofeed start date configured. Defaulting to now."
                    )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector template feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Perform intelligence collection
            stix_objects = self._collect_intelligence(last_run, now)

            if stix_objects:
                stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_bundle, work_id=work_id
                )
                self.helper.connector_logger.info(
                    f"Sent {len(bundles_sent)} STIX bundles to OpenCTI."
                )

            # Update the connector's state
            self.helper.set_state({"last_run": now.isoformat()})
            self.helper.api.work.to_processed(
                work_id, "Connector successfully completed."
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(f"Unexpected error: {str(e)}")

    def run(self):
        """
        Run the main process encapsulated in a scheduler
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )