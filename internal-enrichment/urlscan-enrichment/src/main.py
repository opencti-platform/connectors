from typing import Dict

from pycti import OpenCTIConnectorHelper
from urlscan_enrichment_services.client import UrlscanClient
from urlscan_enrichment_services.config_variables import UrlscanConfig
from urlscan_enrichment_services.constants import UrlscanConstants
from urlscan_enrichment_services.converter_to_stix2 import UrlscanConverter
from urlscan_enrichment_services.utils import UrlscanUtils


class UrlscanConnector:
    """
    Urlscan connector class
    """

    def __init__(self):
        self.config = UrlscanConfig()
        self.helper = OpenCTIConnectorHelper(self.config.load, True)
        self.client = UrlscanClient(self.helper)
        self.converter = UrlscanConverter(self.helper)
        self.constants = UrlscanConstants
        self.utils = UrlscanUtils

        # Define variables
        self.identity = None
        self.tlp = None

    def extract_and_check_markings(self, opencti_entity: dict) -> bool:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI.
        If this is true, we can send the data to connector for enrichment.

        :param opencti_entity: Parameter that contains all information about the entity,
                               including "objectMarking", the marking that the observable uses.
        :return: A boolean
        """

        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                self.tlp = marking_definition["definition"]

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(
            self.tlp, self.config.max_tlp
        )

        return is_valid_max_tlp

    def _generate_labels(self, data: dict) -> list:
        """
        This method allows you to generate specific labels as well as their associated colors

        :param data:
        :return: List
        """
        self.all_labels = []

        if "servers" in data["lists"]:
            # Green flag
            for server in data["lists"]["servers"]:
                self._create_custom_label(f"urlscan: {server}", "#61ff7c")

        if "verdicts" in data:
            if "overall" in data["verdicts"]:
                overall = data["verdicts"]["overall"]
                # Red flag
                if overall["malicious"] is True:
                    self._create_custom_label("urlscan: malicious", "#ff1f53")

                # Orange flag
                if overall["categories"]:
                    for categorie in overall["categories"]:
                        self._create_custom_label(f"urlscan: {categorie}", "#ff801f")

                # Blue flag
                if overall["brands"]:
                    for brand in overall["brands"]:
                        self._create_custom_label(f"urlscan: {brand}", "#5596e3")
                    # White flag
                    if "verticals" in overall["brands"]:
                        for vertical in overall["brands"]["verticals"]:
                            self._create_custom_label(f"urlscan: {vertical}", "#ffffff")

        return self.all_labels

    def _create_custom_label(self, name_label: str, color_label: str):
        """
        This method allows you to create a custom label, using the OpenCTI API.

        :param name_label: A parameter giving the name of the label.
        :param color_label: A parameter giving the color of the label.
        """

        new_custom_label = self.helper.api.label.read_or_create_unchecked(
            value=name_label, color=color_label
        )
        if new_custom_label is None:
            self.helper.connector_logger.error(
                "[ERROR] The label could not be created. "
                "If your connector does not have the permission to create labels, "
                "please create it manually before launching",
                {"name_label": name_label},
            )
        else:
            self.helper.connector_logger.info(
                "[INFO] The label has been created.",
                {"name_label": name_label},
            )
            self.all_labels.append(new_custom_label["value"])

    def _generate_stix_bundle(
        self, data: dict, stix_entity: dict, is_submission: bool
    ) -> str:
        """
        This method create a bundle in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in URLScan.
        :param stix_entity: A parameter that contains all the entity information in OpenCTI.
        :param is_submission: This parameter allows us to identify whether we have a URL or other scopes.
        :return: str bundle
        """
        self.identity = self.converter.generate_urlscan_stix_identity()
        self.stix_objects.append(self.identity)

        self.helper.connector_logger.info(
            "[CONNECTOR] The entity has been identified by URLScan "
            "and generation of the Stix bundle is in progress.",
            {"entity_type": stix_entity["type"], "entity_value": stix_entity["value"]},
        )

        if is_submission is True:
            prepared_file_png = (
                self.utils.prepare_file_png(data)
                if self.config.import_screenshot
                else None
            )
            labels = self._generate_labels(data)
        else:
            prepared_file_png = None
            labels = None

        external_reference = self.converter.generate_stix_external_reference(
            data, stix_entity, is_submission
        )
        stix_observable = self.converter.upsert_stix_observable(
            stix_entity, external_reference, labels, prepared_file_png
        )
        self.stix_objects.append(stix_observable)

        if is_submission is True:
            data_ip_stats = data["stats"]["ipStats"]
            extracted_info_ip = [
                {
                    "domains": item["domains"],
                    "ip": item.get("ip", None) or None,
                    "asn": item["asn"].get("asn", None) or None,
                }
                for item in data_ip_stats
            ]

            merged_data = {}
            for index, item in enumerate(extracted_info_ip):
                domain = tuple(item["domains"])
                if domain in merged_data:
                    merged_entry = merged_data[domain]
                    merged_entry["asn"].append(item["asn"])
                    merged_entry["ip"].append(item["ip"])
                else:
                    merged_data[domain] = {
                        "domains": item["domains"],
                        "asn": [item["asn"]],
                        "ip": [item["ip"]],
                    }

            reorganized_data = [
                {
                    "domains": merged_data[domain]["domains"],
                    "asns": merged_data[domain]["asn"],
                    "ips": merged_data[domain]["ip"],
                }
                for domain in merged_data
            ]

            if len(reorganized_data) > 0:
                for data_stat in reorganized_data:

                    # Generate obs_ipv4 or obs_ipv6
                    stix_obs_ip = self.converter.generate_stix_ip(data_stat)
                    for obs_ip in stix_obs_ip:
                        self.stix_objects.append(obs_ip)

                    # Generate obs_asn
                    stix_obs_asn = self.converter.generate_stix_asn_with_relationship(
                        data_stat, stix_obs_ip
                    )
                    self.stix_objects.extend(stix_obs_asn)

                    if data_stat["domains"][0] in stix_entity["value"]:

                        if self.config.create_indicator:
                            stix_indicator = (
                                self.converter.upsert_stix_indicator_with_relationship(
                                    data,
                                    stix_entity,
                                    external_reference,
                                    labels,
                                    prepared_file_png,
                                )
                            )
                            self.stix_objects.extend(stix_indicator)

                        for index, ip in enumerate(data_stat["ips"]):
                            if ip is None:
                                continue

                            if self.config.create_indicator:
                                # Generate Relationship : Indicator -> "based-on" -> obs_ip
                                indicator_to_ip = (
                                    self.converter.generate_stix_relationship(
                                        stix_indicator[0].id,
                                        "based-on",
                                        stix_obs_ip[index].id,
                                    )
                                )
                                self.stix_objects.append(indicator_to_ip)

                            # Generate Relationship : Observable -> "related-to" -> obs_ip
                            observable_to_ip = (
                                self.converter.generate_stix_relationship(
                                    stix_entity["id"],
                                    "related-to",
                                    stix_obs_ip[index].id,
                                )
                            )
                            self.stix_objects.append(observable_to_ip)

                    else:

                        # Generate obs_hostname
                        stix_obs_hostname = (
                            self.converter.generate_stix_hostname_with_relationship(
                                data_stat,
                                stix_entity,
                                stix_obs_ip,
                                external_reference,
                                labels,
                                prepared_file_png,
                            )
                        )
                        self.stix_objects.extend(stix_obs_hostname)

        filtered_list = [x for x in self.stix_objects if x is not None]
        stix_no_relationship = [x for x in filtered_list if x["type"] != "relationship"]
        stix_relationship = [x for x in filtered_list if x["type"] == "relationship"]
        reordered_data = stix_no_relationship + stix_relationship

        self.helper.connector_logger.info(
            "[CONNECTOR] For this entity, the number of Stix bundle(s) that will be enriched.",
            {
                "Entity": stix_entity["value"],
                "Stix_bundle_length": len(reordered_data),
            },
        )

        stix2_bundle = self.helper.stix2_create_bundle(reordered_data)
        return stix2_bundle

    def _process_message(self, data: Dict) -> str:

        # OpenCTI entity information retrieval
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]
        self.stix_objects = data["stix_objects"]

        # Security to limit playbook triggers to something other than the scope initial
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = stix_entity["type"].lower()

        if entity_type in scopes:

            is_valid_max_tlp = self.extract_and_check_markings(opencti_entity)
            if not is_valid_max_tlp:
                raise ValueError(
                    "[ERROR] Do not send any data, TLP of the observable is greater than MAX TLP, "
                    "the connector does not has access to this observable, please check the group of the connector user"
                )

            if opencti_entity["entity_type"] == "StixFile":
                if "SHA-256" in stix_entity["hashes"]:
                    opencti_entity_value = stix_entity["hashes"]["SHA-256"]
                else:
                    return "[CONNECTOR] Only the SHA-256 hash is correctly interpreted by URLScan"

            else:
                # Extract Value from opencti entity data for (Url, IPv4-Addr, IPv6-Addr, Domain-Name, Hostname)
                opencti_entity_value = stix_entity["value"]

            try:
                stix_entity_type = stix_entity["type"]
                if (
                    stix_entity_type == "url"
                    or stix_entity_type == "domain-name"
                    or stix_entity_type == "hostname"
                ):

                    # Check Urlscan User Quota API Response
                    self.client.check_urlscan_user_quota(self.config.visibility)

                    # Post Urlscan Submission API Response
                    # https://urlscan.io/docs/
                    json_submission = self.client.urlscan_submission(
                        opencti_entity_value
                    )

                    uuid = json_submission["uuid"]
                    self.helper.connector_logger.info(
                        "[INFO-SUBMISSION] The urlscan submission request generated the uuid:",
                        {"uuid": uuid, "entity_value": str(opencti_entity_value)},
                    )

                    json_result = self.client.urlscan_result(uuid)

                    # Generate a stix bundle
                    stix_bundle = self._generate_stix_bundle(
                        json_result, stix_entity, True
                    )

                    # Send stix2 bundle
                    bundles_sent = self.helper.send_stix2_bundle(stix_bundle)
                    return (
                        "[CONNECTOR] Sent "
                        + f"{len(bundles_sent)}"
                        + " stix bundle(s) for worker import"
                    )

                elif entity_type in self.constants.ENTITY_TYPE_MAP_SEARCH_API:

                    json_search = {}
                    # Generate a stix bundle
                    stix_bundle = self._generate_stix_bundle(
                        json_search, stix_entity, False
                    )
                    # Send stix2 bundle
                    bundles_sent = self.helper.send_stix2_bundle(stix_bundle)
                    return (
                        "[CONNECTOR] Sent "
                        + f"{len(bundles_sent)}"
                        + " stix bundle(s) for worker import"
                    )
                else:
                    raise ValueError(
                        "[ERROR] This entity type is currently not managed, "
                        "available_type: Url, Hostname, Domain-Name, IPv4-Addr, IPv6-Addr"
                    )

            except Exception as e:
                raise ValueError(str(e))
        else:

            return self.helper.connector_logger.info(
                "[INFO] The trigger does not concern the initial scope found in the config connector, "
                "maybe choose a more specific filter in the playbook",
                {"entity_id": data["entity_id"]},
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    urlscanInstance = UrlscanConnector()
    urlscanInstance.start()
