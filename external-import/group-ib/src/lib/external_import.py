import sys
import time
from datetime import datetime
from traceback import format_exc
from typing import Any

import stix2
from config import ConfigConnector
from cyberintegrations import TIAdapter
from cyberintegrations.decorators import cache_data
from cyberintegrations.utils import ProxyConfigurator
from pycti import OpenCTIConnectorHelper
from utils import ExternalImportHelper


@cache_data(
    cache_dir=ConfigConnector.MITRE_CACHE_FOLDER,
    cache_file=ConfigConnector.MITRE_CACHE_FILENAME,
    ttl=1,
)
def get_mitre_mapper(adapter, endpoint, params, decode=True, **kwargs):
    # type: (TIAdapter, str, dict, bool, dict) -> dict
    mitre_mapper = {}

    response = adapter.send_request(
        endpoint=endpoint, params=params, decode=decode, **kwargs
    )

    for pattern_dictionary in response.get("AttackPattern").values():
        name = pattern_dictionary.get("name", "")
        if name[0] == "[":
            name = name[1:-1:]
            name = name.split("->")[-1]
        mitre_mapper[pattern_dictionary.get("mitreId")] = name

    return mitre_mapper


class ExternalImportConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use.
            Specifies the time interval in ISO 8601 format (Duration):
                Format: P[n]Y[n]M[n]DT[n]H[n]M[n]S
                - P: indicates the beginning of the period (Period).
                - T: separates date and time, used before time components.
                - n: a number representing a quantity (e.g. 3 for 3 minutes).

                Examples:
                - PT3M: an interval of 3 minutes.
                - PT5S: an interval of 5 seconds.
                - P1DT2H: an interval of 1 day and 2 hours.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.cfg = ConfigConnector()
        self.helper = OpenCTIConnectorHelper({})
        self.pc = ProxyConfigurator()

        current_state = self.helper.get_state()

        # Specific connector attributes for external import connectors
        self.interval = ExternalImportHelper.validation_interval(
            cfg=self.cfg, helper=self.helper
        )
        self.update_existing_data = (
            ExternalImportHelper.validation_update_existing_data(
                cfg=self.cfg, helper=self.helper
            )
        )
        self.ttl = None

        # Global collections filters
        self.IGNORE_NON_MALWARE_DDOS = False
        self.IGNORE_NON_INDICATOR_THREATS = False
        self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = False

        # Proxy initialization
        self.proxies = self.pc.get_proxies(
            proxy_ip=self.cfg.ti_api_proxy_ip,
            proxy_port=self.cfg.ti_api_proxy_port,
            proxy_protocol=self.cfg.ti_api_proxy_protocol,
            proxy_username=self.cfg.ti_api_proxy_username,
            proxy_password=self.cfg.ti_api_proxy_password,
        )
        # Collections initialization
        self.enabled_collections = []
        for (
            collection_name,
            slached_collection_name,
        ) in ConfigConnector.collection_map.items():
            enable = self.cfg.get_collection_settings(collection_name, "enable")
            if enable == True:
                self.enabled_collections.append(slached_collection_name)

        # TI API initialization
        self.ti_adapter = TIAdapter(
            ti_creds_dict={
                "api_key": self.cfg.ti_api_token,
                "username": self.cfg.ti_api_username,
            },
            proxies=self.proxies,
            config_obj=self.cfg,
            api_url=self.cfg.ti_api_url,
            enabled_collections=self.enabled_collections,
            collection_mapping_config=self.cfg.collection_mapping_config,
            collections_last_sequence_updates=current_state,
        )
        self.helper.log_info(f"Initialized TI Adapter, {self.ti_adapter}")
        # create list of collections feeds generators
        self.MITRE_MAPPER = None

    def _collect_intelligence(
        self, collection, ttl, portion, mitre_mapper, flag=False
    ) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError

    def check_generator(self, generator, collection):
        if not generator:
            self.helper.log_warning(
                "No generator for collection: {}".format(collection)
            )
            return False
        return True

    def check_enable(self, enable, collection):
        if not enable:
            self.helper.log_warning(
                "User disable collection: {}. Aborting!".format(collection)
            )
            return False
        return True

    def extra_pre_processing(self, collection, portion) -> None | Any:
        parsed_portion = None
        if collection == "attacks/ddos" and self.IGNORE_NON_MALWARE_DDOS:
            parsed_portion = portion.parse_portion(
                filter_map=[("malware", [])],
                check_existence=True,
            )
        elif (
            collection in ["apt/threat", "hi/threat"]
            and self.IGNORE_NON_INDICATOR_THREATS
        ):
            parsed_portion = portion.parse_portion(
                filter_map=[("indicators", [])],
                check_existence=True,
            )
        else:
            parsed_portion = portion.parse_portion()

        return parsed_portion

    def get_formatted_utcfromtimestamp(self, date) -> str:
        return datetime.utcfromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S")

    def set_or_update_state(
        self, timestamp: int | None = None, prepared_data: dict | None = None
    ):
        current_state = self.helper.get_state()
        if current_state:
            if timestamp:
                current_state["last_run"] = timestamp
            elif prepared_data:
                current_state.update(prepared_data)
        else:
            if timestamp:
                current_state = {"last_run": timestamp}
            elif prepared_data:
                current_state = prepared_data

        self.helper.set_state(current_state)

    def get_last_run(self, current_state: dict | None):
        if current_state is not None and "last_run" in current_state:
            last_run = current_state["last_run"]
            self.helper.log_info(
                f"{self.helper.connect_name} connector last run: "
                f"{self.get_formatted_utcfromtimestamp(date=last_run)}"
            )
        else:
            last_run = None
            self.helper.log_info(f"{self.helper.connect_name} connector has never run")
        return last_run

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                last_run = self.get_last_run(current_state=current_state)

                # If the last_run is None or the required interval has passed since last_run
                interval_seconds = ExternalImportHelper.get_interval(
                    interval=self.interval, helper=self.helper
                )
                if last_run is None or (timestamp - last_run >= interval_seconds):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    friendly_name = f"{self.helper.connect_name} run @ {self.get_formatted_utcfromtimestamp(date=timestamp)}"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    try:
                        # create list of collections feeds generators
                        data = self.ti_adapter.create_generators(sleep_amount=1)
                        self.helper.log_debug(f"Generators data {data} {type(data)}")

                        # MITRE
                        self.MITRE_MAPPER = get_mitre_mapper(
                            adapter=self.ti_adapter,
                            endpoint="common/matrix/vocab/techniques",
                            params={},
                        )

                        ###
                        for data_item in data:
                            prepared_data = data_item[1]
                            self.helper.log_debug(
                                f"Generator prepared data {prepared_data}"
                            )
                            collection = data_item[0][0]
                            generator = data_item[0][1]
                            self.helper.log_debug(
                                f"Generator data collection:{collection} , generator: {generator}"
                            )
                            collection_name_for_config_map = collection.replace(
                                "/", "_"
                            )
                            time.sleep(3)

                            if not self.check_generator(
                                generator=generator, collection=collection
                            ):
                                continue

                            enable = self.cfg.get_collection_settings(
                                collection_name_for_config_map, "enable"
                            )

                            if not self.check_enable(
                                enable=enable, collection=collection
                            ):
                                continue

                            # TTL
                            ttl = self.cfg.get_collection_settings(
                                collection_name_for_config_map, "ttl"
                            )
                            self.ttl = int(ttl)

                            # Global collections filters

                            self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = (
                                self.cfg.get_extra_settings_by_name(
                                    "intrusion_set_instead_of_threat_actor"
                                )
                            )

                            self.IGNORE_NON_MALWARE_DDOS = (
                                self.cfg.get_extra_settings_by_name(
                                    "ignore_non_malware_ddos"
                                )
                            )

                            self.IGNORE_NON_INDICATOR_THREATS = (
                                self.cfg.get_extra_settings_by_name(
                                    "ignore_non_indicator_threats"
                                )
                            )

                            for portion in generator:
                                # Extra pre-processing for collections
                                parsed_portion = self.extra_pre_processing(
                                    collection=collection, portion=portion
                                )
                                size = len(parsed_portion)
                                count = 0
                                for event in parsed_portion:
                                    count += 1
                                    self.helper.log_info(f"Parsing {count}/{size}")

                                    bundle_objects = self._collect_intelligence(
                                        collection,
                                        self.ttl,
                                        event,
                                        self.MITRE_MAPPER,
                                        flag=self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR,
                                    )
                                    bundle = stix2.Bundle(
                                        objects=bundle_objects, allow_custom=True
                                    ).serialize()

                                    self.helper.log_info(
                                        f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                                    )
                                    self.helper.send_stix2_bundle(
                                        bundle,
                                        update=self.update_existing_data,
                                        work_id=work_id,
                                    )
                                    self.helper.log_debug(
                                        f"Sending {str(bundle_objects)} STIX objects to OpenCTI..."
                                    )

                                # Update seqUpdate param
                                prepared_data[collection].update(
                                    {"sequpdate": portion.sequpdate}
                                )
                                self.set_or_update_state(prepared_data=prepared_data)

                    except Exception:
                        self.helper.log_error(format_exc())

                    # Store the current timestamp as a last run
                    message = f"{self.helper.connect_name} connector successfully run, storing last_run as {timestamp}"
                    self.helper.log_info(message)

                    self.helper.log_info(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    self.set_or_update_state(timestamp=timestamp)
                    self.helper.api.work.to_processed(work_id, message)
                    next_run_it = ExternalImportHelper.get_next_run_it(
                        interval=self.interval,
                        helper=self.helper,
                        timestamp=timestamp,
                        last_run=last_run,
                    )
                    self.helper.log_info(f"Last_run stored, next run in: {next_run_it}")
                else:
                    self.helper.metric.state("idle")
                    next_run_it = ExternalImportHelper.get_next_run_it(
                        interval=self.interval,
                        helper=self.helper,
                        timestamp=timestamp,
                        last_run=last_run,
                    )
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, "
                        f"next run in:  {next_run_it} "
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception:
                self.helper.metric.inc("error_count")
                self.helper.metric.state("stopped")
                self.helper.log_error(format_exc())

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)
