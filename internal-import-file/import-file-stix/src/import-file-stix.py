import json
import os
import sys
import time
from typing import Dict, List

import yaml
from pycti import OpenCTIConnectorHelper
from stix2elevator import elevate
from stix2elevator.options import initialize_options


class ImportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data: Dict) -> str:
        file_fetch = data["file_fetch"]
        bypass_validation = data["bypass_validation"]
        file_markings = data.get("file_markings", [])
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info(f"Importing the file {file_uri}")

        file_content = self.helper.api.fetch_opencti_file(file_uri)
        if data["file_mime"] == "text/xml":
            self.helper.log_debug("STIX 1.2 file. Attempting conversion")
            initialize_options()
            file_content = elevate(file_content)
        entity_id = data.get("entity_id", None)
        if entity_id:
            self.helper.log_info("Contextual import.")
            bundle = json.loads(file_content)["objects"]
            bundle = self._update_container(bundle, entity_id)
            file_content = self.helper.stix2_create_bundle(bundle)
        bundles_sent = self.helper.send_stix2_bundle(
            file_content,
            bypass_validation=bypass_validation,
            file_name=data["file_id"],
            entity_id=entity_id,
            file_markings=file_markings,
        )
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)

    @staticmethod
    def _is_container(element_type: str):
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
        for elem in bundle:
            if self._is_container(elem.get("type")):
                return True
        return False

    def _update_container(self, bundle: List, entity_id: int) -> List:
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
        connectorImportFileStix = ImportFileStix()
        connectorImportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
