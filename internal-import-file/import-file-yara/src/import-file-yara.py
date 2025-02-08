import datetime
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

import plyara
import stix2
import yaml
from plyara.utils import rebuild_yara_rule
from pycti import Indicator, OpenCTIConnectorHelper, get_config_variable


class ImportFileYARA:

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        self.yara_import_file_split_rules = get_config_variable(
            "YARA_IMPORT_FILE_SPLIT_RULES",
            ["yara_import_file", "split_rules"],
            config,
            isNumber=False,
            default=True,
        )
        self.parser = plyara.Plyara()

    def _convert_yara_rule_to_stix_indicator(
        self, yara_rule: str, yara_name: str, yara_metadata: List
    ) -> Indicator:
        """
        :param yara_rule:
        :param yara_name:
        :param yara_metadata:
        :return:
        """
        rule_description = None
        rule_labels = []
        rule_reference = None
        for value in yara_metadata:
            for key in value.keys():
                if key.lower() == "description":
                    rule_description = value.get(key)
                if key.lower() == "labels" or key.lower() == "tags":
                    rule_labels = value.get(key)
                if key.lower() == "reference":
                    rule_reference = value.get(key)

        external_references = []
        if rule_reference:
            external_reference = stix2.ExternalReference(
                source_name="YARA importer",
                url=rule_reference,
            )
            external_references.append(external_reference)

        pattern = yara_rule
        pattern_type = "yara"
        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=yara_name,
            description=rule_description,
            confidence=self.helper.connect_confidence_level,
            pattern_type=pattern_type,
            pattern=pattern,
            labels=rule_labels,
            created_by_ref=None,
            object_marking_refs=[],
            external_references=external_references,
            created=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            valid_from=datetime.datetime.now(datetime.UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
                "x_opencti_score": 100,
            },
        )
        return indicator

    def _parse_yara_file(self, content: str, filename: str) -> List:
        """
        :param content:
        :return:
        """
        bundle_objects = []
        if self.yara_import_file_split_rules:
            parsing_result = self.parser.parse_string(content)
            self.helper.log_info(
                f"Processing a YARA file containing: {len(parsing_result)} rules"
            )
            for rule in parsing_result:
                rule_name = rule.get("rule_name")
                rule_metadata = rule.get("metadata")
                self.helper.log_debug(f"Processing rule name : {rule_name}")
                yara_content = rebuild_yara_rule(rule, condition_indents=True)
                stix_indicator = self._convert_yara_rule_to_stix_indicator(
                    yara_rule=yara_content,
                    yara_name=rule_name,
                    yara_metadata=rule_metadata,
                )
                bundle_objects.append(stix_indicator)
        else:
            # get yara indicator name from filename
            stix_indicator = self._convert_yara_rule_to_stix_indicator(
                yara_rule=content, yara_name=filename, yara_metadata=[]
            )
            bundle_objects.append(stix_indicator)

        # reset plyara state
        self.parser.clear()
        return bundle_objects

    def _process_message(self, data: Dict) -> str:
        """
        :param data:
        :return:
        """
        file_fetch = data["file_fetch"]
        filename = Path(file_fetch).name
        bypass_validation = data["bypass_validation"]
        file_markings = data.get("file_markings", [])
        file_uri = self.helper.opencti_url + file_fetch

        file_content = self.helper.api.fetch_opencti_file(file_uri)
        bundle_objects = self._parse_yara_file(content=file_content, filename=filename)

        # get related entity_id
        entity_id = data.get("entity_id", None)

        bundle_json = stix2.Bundle(
            objects=bundle_objects, allow_custom=True
        ).serialize()

        if entity_id:
            self.helper.log_info("Contextual import.")
            bundle = json.loads(bundle_json)["objects"]
            bundle = self._update_container(bundle, entity_id)
            bundle_json = self.helper.stix2_create_bundle(bundle)

        bundles_sent = self.helper.send_stix2_bundle(
            bundle_json,
            bypass_validation=bypass_validation,
            file_name=data["file_id"] + ".json",
            entity_id=entity_id,
            file_markings=file_markings,
        )
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        """
        :return:
        """
        self.helper.listen(self._process_message)

    @staticmethod
    def _is_container(element_type: str):
        """
        :param element_type:
        :return:
        """
        return (
            element_type == "report"
            or element_type == "grouping"
            or element_type == "observed-data"
            or element_type == "x-opencti-case-incident"
            or element_type == "x-opencti-case-rfi"
            or element_type == "x-opencti-case-rft"
            or element_type == "x-opencti-task"
            or element_type == "x-opencti-feedback"
        )

    def _contains_container(self, bundle: List) -> bool:
        """
        :param bundle:
        :return:
        """
        for elem in bundle:
            if self._is_container(elem.get("type")):
                return True
        return False

    def _update_container(self, bundle: List, entity_id: int) -> List:
        """
        :param bundle:
        :param entity_id:
        :return:
        """
        container = self.helper.api.stix_domain_object.read(id=entity_id)
        container_stix_bundle = (
            self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type=container["entity_type"], entity_id=container["id"]
            )
        )
        if len(container_stix_bundle["objects"]) > 0:
            container_stix = [
                object
                for object in container_stix_bundle["objects"]
                if "x_opencti_id" in object
                and object["x_opencti_id"] == container["id"]
            ][0]
            if self._is_container(container_stix.get("type")):
                if self._contains_container(bundle):
                    self.helper.log_info("Bundle contains container.")
                    container_stix["object_refs"] = []
                    for elem in bundle:
                        if self._is_container(elem.get("type")):
                            container_stix["object_refs"].append(elem["id"])
                            if "object_refs" in elem:
                                for object_id in elem.get("object_refs"):
                                    container_stix["object_refs"].append(object_id)
                else:
                    self.helper.log_info(
                        "No container in Stix file. Updating current container"
                    )
                    container_stix["object_refs"] = [object["id"] for object in bundle]
                bundle.append(container_stix)
        return bundle


if __name__ == "__main__":
    try:
        connectorImportFileYARA = ImportFileYARA()
        connectorImportFileYARA.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
