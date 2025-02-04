import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from typing import Any, Generator

from connector.models import DomainReputationModel, IPReputationModel
from connector.services import (
    ConverterToStix,
    DateTimeFormat,
    ProofpointEtReputationClient,
    ProofpointEtReputationConfig,
    Utils,
)
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError


class ReputationEntity(Enum):
    IP = "iprepdata"
    DOMAIN = "domainrepdata"


class ProofpointEtReputationConnector:

    def __init__(self):
        """
        Initialize the connector with the required configurations.
        """

        # Load configuration file and connection helper
        self.config = ProofpointEtReputationConfig()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ProofpointEtReputationClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)
        self.utils = Utils()

    def _process_initiate_work(self, collection: str, now_isoformat: str) -> str:
        """
        Starts a work collection process. only one work per collection.
        Sends a request to the API with the initiate_work method to initialize the work.

        Args:
            collection (str): The type of collection being processed ("IPv4-Addr" or "Domain-Name").
            now_isoformat (str): Reference is used to inform the user when the work will begin.

        Returns:
            str: The work ID generated by the API when initiating the work collection.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting work collection...",
            {"collection": collection, "isoformat": now_isoformat},
        )
        source_collection = (
            "iprepdata" if collection == "IPv4-Addr" else "domainrepdata"
        )
        friendly_name = f"ProofPoint ET Reputation - {collection} ({source_collection}) run @ {now_isoformat}"
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _process_send_stix_to_opencti(
        self, work_id: str, prepared_objects: list
    ) -> None:
        """
        This method prepares and sends unique STIX objects to OpenCTI.
        This method takes a list of objects prepared by the models, extracts their STIX representations, creates a serialized STIX bundle and It then sends this bundle to OpenCTI.
        If prepared objects exist, the method ensures that only unique objects with an 'id' attribute are included. After sending the STIX objects, it keeps inform of the number of bundles sent.

        Args:
            work_id (str): The unique identifier for the work process associated with the STIX objects.
            prepared_objects (list): A list of objects containing STIX representations to be sent to OpenCTI.

        Returns:
            None
        """
        if prepared_objects is not None and len(prepared_objects) != 0:
            # Filters objects to retain only those with a unique ID, preventing duplication in the final list.
            unique_ids = set()
            get_stix_representation_objects = [
                obj.stix2_representation
                for obj in prepared_objects
                if obj.id not in unique_ids and not unique_ids.add(obj.id)
            ]

            stix_objects_bundle = self.helper.stix2_create_bundle(
                get_stix_representation_objects
            )
            bundles_sent = self.helper.send_stix2_bundle(
                stix_objects_bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Sending STIX objects to OpenCTI...",
                {"bundles_sent": len(bundles_sent)},
            )

    def _process_complete_work(self, collection: str, work_id: str) -> None:
        """
        Marks the work collection process as complete.
        This method logs the completion of the work collection for a specific work ID.
        Sends a request to the API with the to_processed method to complete the work.

        Args:
            collection (str): The type of collection being processed ("IPv4-Addr" or "Domain-Name").
            work_id (str): The unique identifier of the work collection to mark as complete.

        Returns:
            None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Complete work collection...",
            {"collection": collection, "work_id": work_id},
        )
        message = "ProofPoint ET Reputation - Finished work"
        self.helper.api.work.to_processed(work_id, message)

    def _process_reputation_tasks(self) -> None:
        """
        Process reputation-related tasks asynchronously.

        This method submits two tasks to a thread pool executor to fetch reputation data for IP addresses and domains
        from the client. Once the tasks are completed, it processes the results by generating STIX objects and sending
        them to OpenCTI. This method also ensures that the work is always completed if it was initialized correctly.

        The tasks are as follows
            - Recover IP address reputation from ProofPoint ET Reputation.
            - Recover domain reputation from ProofPoint ET Reputation.

        Returns:
            None
        """
        with ThreadPoolExecutor(max_workers=2) as executor:

            tasks = {
                executor.submit(
                    self.client.proofpoint_get_ips_reputation, ReputationEntity.IP.value
                ): "IPv4-Addr",
                executor.submit(
                    self.client.proofpoint_get_domains_reputation,
                    ReputationEntity.DOMAIN.value,
                ): "Domain-Name",
            }

            for completed_task in as_completed(tasks):
                collection = tasks[completed_task]
                task_result = completed_task.result()
                if task_result.get("error"):
                    self.helper.connector_logger.error(
                        task_result.get("message"),
                        {"collection": collection, "error": task_result.get("error")},
                    )
                    continue
                now_isoformat = self.utils.get_now(DateTimeFormat.ISO)
                work_id = self._process_initiate_work(collection, now_isoformat)
                try:
                    prepared_objects = self._generate_stix_from_reputation_data(
                        task_result, collection
                    )
                    self._process_send_stix_to_opencti(work_id, prepared_objects)
                except Exception as err:
                    self.helper.connector_logger.error(
                        "[ERROR] An unknown error occurred during the reputation handling process.",
                        {"collection": collection, "error": err},
                    )
                finally:
                    if work_id:
                        self._process_complete_work(collection, work_id)

    def _generate_reputation_model(
        self, data_list: dict[str, dict[str, str]], collection: str
    ) -> Generator[IPReputationModel | DomainReputationModel | None, None, None]:
        """
        Generates reputation models from a list of data.

        This method iterates through a dictionary of entities and their scores (including categories and their
        associated scores), generating `IPReputationModel` or `DomainReputationModel` objects depending on the
        type of collection. If a model cannot be validated by pydantic, or some other error occurs, the error
        is reported and the entity is ignored.

        Args:
            data_list (dict[str, dict[str, str]]): A dictionary where the keys are entities ("IPv4-Addr", "Domain-Name")
             and the values are dictionaries of categories and their associated scores.
            collection (str): The type of collection being processed ("IPv4-Addr" or "Domain-Name").

        Returns:
            Generator[IPReputationModel | DomainReputationModel | None, None, None]: A reputation model object for each
            valid entity, or `None` if the model generation fails.
        """
        for entity, scores in data_list.items():
            try:
                if collection == "IPv4-Addr":
                    yield IPReputationModel(value=entity, score_by_category=scores)
                elif collection == "Domain-Name":
                    yield DomainReputationModel(value=entity, score_by_category=scores)
            except ValidationError as err:
                self.helper.connector_logger.debug(
                    "[CONNECTOR] Model validation: The entity or reputation score does not conform to the schema. "
                    "The entity has been ignored.",
                    {
                        "collection": collection,
                        "entity": entity,
                        "category_and_score": scores,
                        "error": err,
                    },
                )
                continue
            except Exception as err:
                self.helper.connector_logger.error(
                    "[ERROR] An unknown error has occurred during the generation of the reputation model.",
                    {
                        "collection": collection,
                        "entity": entity,
                        "category_and_score": scores,
                        "error": err,
                    },
                )

    def _generate_stix_from_reputation_data(
        self, data_list: dict, collection: str
    ) -> list:
        """
        This method generates objects and their STIX representations from reputation data extracted from the ProofPoint
        ET Reputation database. It creates observables, indicators and their relationships according to configuration
        parameters. Only the creation of observables is mandatory, while indicators and their relationships are
        optional, depending on the configuration.

        A filtering process is applied using a minimum score defined in the connector configuration
        (default: 20. Note that ProofPoint does not store entities with scores below 20).

        If an entity has multiple scores due to multiple categories, the highest score is used for filtering.
        If the score is greater than 100, it is capped at 100 because that is the maximum supported by OpenCTI.
        Entities with a score lower than the configured minimum score are ignored.

        Args:
            data_list (dict): Contain reputation data for entities, with their associated scores and categories.
            collection (str): The type of collection being processed ("IPv4-Addr" or "Domain-Name").

        Returns:
            list: A list of generated objects, including author, marking, observables, indicators, and relationships.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting the generation of stix objects from the ProofPoint ET Reputation database for the collection...",
            {"collection": collection},
        )
        stix_objects: list[Any] = []

        # Make author object
        author = self.converter_to_stix.make_author()
        stix_objects.append(author)

        # Make marking definition object
        marking_definition = (
            self.converter_to_stix.make_marking_definition_tlp_amber_strict()
        )
        stix_objects.append(marking_definition)

        for model in self._generate_reputation_model(data_list, collection):
            # Recovery of the highest value in the scores
            highest_score = max(model.score_by_category.values())

            # Given that the maximum score for OpenCTI is 100, we have decided to limit all higher scores,
            # as defined by ProofPoint ET Reputation, to 100.
            highest_score_converted = 100 if highest_score > 100 else highest_score

            # All categories will be used to generate labels
            list_categories = list(model.score_by_category.keys())

            if self.config.extra_min_score > highest_score_converted:
                self.helper.connector_logger.debug(
                    "[CONNECTOR] The creation of the entity was ignored due to your configuration of the min_score variable.",
                    {
                        "collection": collection,
                        "min_score_config": self.config.extra_min_score,
                        "entity": model.value,
                        "entity_score": highest_score_converted,
                    },
                )
                continue

            # Make observable object
            observable = self.converter_to_stix.make_observable(
                model.value, highest_score_converted, list_categories, collection
            )
            if observable is None:
                continue
            self.helper.connector_logger.debug(
                "[CONNECTOR] The generation of observable in stix2 from reputation data has been a success.",
                {
                    "observable_id": observable.id,
                    "observable_value": observable.value,
                },
            )
            stix_objects.append(observable)

            if self.config.extra_create_indicator:
                # Make indicator object
                indicator = self.converter_to_stix.make_indicator(
                    model.value,
                    highest_score_converted,
                    list_categories,
                    collection,
                )
                self.helper.connector_logger.debug(
                    "[CONNECTOR] The generation of indicator in stix2 from reputation data has been a success.",
                    {
                        "indicator_id": indicator.id,
                        "indicator_name": indicator.name,
                    },
                )
                stix_objects.append(indicator)

                # Make relationship object between indicator and observable
                relationship = self.converter_to_stix.make_relationship(
                    indicator, "based-on", observable
                )
                self.helper.connector_logger.debug(
                    "[CONNECTOR] The generation of the relationship between the observable and the indicator was a success.",
                    {
                        "relationship_id": relationship.id,
                        "source_ref": indicator.id,
                        "relationship_type": relationship.relationship_type,
                        "target_ref": observable.id,
                    },
                )
                stix_objects.append(relationship)

        self.helper.connector_logger.info(
            "[CONNECTOR] Finalisation of the generation of stix objects from the ProofPoint ET Reputation database for the collection...",
            {
                "collection": collection,
                "generated_entities": len(stix_objects),
                "config_min_score": self.config.extra_min_score,
            },
        )
        return stix_objects

    def process_message(self) -> None:
        """
        The main process used by the connector to collect intelligence
        This method launches the connector, processes the current state, collects reputation data for each different
        collection (IPv4, Domain Name) and updates the state of the last successful execution.

        Returns:
            None
        """
        try:
            get_now = self.utils.get_now()
            connector_start_timestamp = get_now.get("now_timestamp")
            connector_start_isoformat = get_now.get("now_isoformat")

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting the connector...",
                {
                    "connector_name": self.helper.connect_name,
                    "connector_start": connector_start_isoformat,
                },
            )

            # Get the current state
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                last_run_isoformat = datetime.fromtimestamp(last_run).isoformat(
                    sep=" ", timespec="seconds"
                )
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run...",
                    {
                        "last_run_timestamp": last_run,
                        "last_run_isoformat": last_run_isoformat,
                    },
                )
            else:
                last_run = "Never run"
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Processing reputation-related collection
            self._process_reputation_tasks()

            # Store the current timestamp as a last run of the connector
            connector_stop = self.utils.get_now(DateTimeFormat.ISO)
            self.helper.connector_logger.info(
                "[CONNECTOR] Getting current state and update it with last run of the connector.",
                {"current_state": current_state},
            )

            if current_state:
                current_state["last_run"] = connector_start_timestamp
            else:
                current_state = {"last_run": connector_start_timestamp}
            self.helper.set_state(current_state)

            self.helper.connector_logger.info(
                "[CONNECTOR] The connector has been successfully run, saving the last_run.",
                {
                    "old_last_run_timestamp": last_run,
                    "new_last_run_timestamp": connector_start_timestamp,
                    "connector_startup": connector_start_isoformat,
                    "connector_stop": connector_stop,
                },
            )

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
        Schedules the connector to run periodically.
        This method uses the provided duration period in the config to schedule the main processing function.

        Returns:
            None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector_duration_period,
        )
