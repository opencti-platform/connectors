import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import cached_property
from posixpath import join as urljoin
from typing import Any, Dict, Iterable, List, Set

import requests
import yaml
from dateutil.parser import ParserError, parse
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, get_config_variable
from requests import RequestException

## MODIFICATION BY CYRILYXE (OPENCTI 6.0.5, the 2022-08-12)
# By default, the def '_load_data_sets' (line 370ish in this file) uses relative path
#   But from a manual deployement, we have to use a Daemon for launching the service
#   So i added a global var : gbl_scriptDir (not mandatory but for visibility purpose only)
gbl_scriptDir: str = os.path.dirname(os.path.realpath(__file__))


# so i propose the change on the relative path with the concat of the script dir path (go to line 374)


class Sekoia(object):
    limit = 200

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self._cache = {}
        # Extra config
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT60S",
        )

        self.base_url = self.get_config("base_url", config, "https://api.sekoia.io")
        self.start_date: str = self.get_config("start_date", config, None)
        self.collection = self.get_config(
            "collection", config, "d6092c37-d8d7-45c3-8aff-c4dc26030608"
        )
        self.create_observables = self.get_config("create_observables", config, True)
        self.import_source_list = get_config_variable(
            "SEKOIA_IMPORT_SOURCE_LIST",
            ["sekoia", "import_source_list"],
            config,
            default=False,
        )
        self.all_labels = []

        self.helper.log_info("Setting up api key")
        self.api_key = self.get_config("api_key", config)
        if not self.api_key:
            self.helper.log_error("API key is Missing")
            raise ValueError("API key is Missing")

        self._load_data_sets()
        self.helper.log_info("All datasets has been loaded")

        self.helper.api.identity.create(
            stix_id="identity--357447d7-9229-4ce1-b7fa-f1b83587048e",
            type="Organization",
            name="SEKOIA",
            description="SEKOIA.IO is a European cybersecurity SaaS company, whose mission is to develop the best protection capabilities against cyber attacks.",
        )
        self.helper.api.marking_definition.create(
            stix_id="marking-definition--bf973641-9d22-45d7-a307-ccdc68e120b9",
            definition_type="statement",
            definition="Copyright SEKOIA.IO",
        )

    @cached_property
    def requested_types(self) -> str:
        return self.helper.connect_scope

    def process_message(self):
        self.helper.log_info("Starting SEKOIA.IO connector")
        state = self.helper.get_state() or {}
        cursor = state.get("last_cursor", self.generate_first_cursor())
        self.helper.log_info(f"Starting with {cursor}")

        friendly_name = "SEKOIA run @ " + datetime.now(timezone.utc).isoformat()
        try:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            cursor = self._run(cursor, work_id)
            message = f"Connector successfully run, cursor updated to {cursor}"
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            self.helper.api.work.to_processed(work_id, "Connector is stopping")
            sys.exit(0)
        except Exception as ex:
            # In case of error try to get the last updated cursor
            # since `_run` updates it after every successful request
            state = self.helper.get_state() or {}
            cursor = state.get("last_cursor", cursor)
            self.helper.log_error(str(ex))
            message = f"Connector encountered an error, cursor updated to {cursor}"
            self.helper.api.work.to_processed(work_id, message)

    def run(self):
        self.helper.schedule_iso(
            message_callback=self.process_message, duration_period=self.duration_period
        )

    @staticmethod
    def get_config(name: str, config, default: Any = None):
        env_name = f"SEKOIA_{name.upper()}"
        result = get_config_variable(env_name, ["sekoia", name], config)
        return result or default

    def get_collection_url(self):
        return urljoin(
            self.base_url, "v2/inthreat/collections", self.collection, "objects"
        )

    def get_relationship(self, indicator_id: str):
        return urljoin(
            self.base_url, "v2/inthreat/objects", indicator_id, "relationships"
        )

    def get_object_url(self, ids: Iterable):
        return urljoin(self.base_url, "v2/inthreat/objects", ",".join(ids))

    def get_relationship_url(self, ids: Iterable):
        return urljoin(self.base_url, "v2/inthreat/relationships", ",".join(ids))

    def get_file_url(self, item_id: str, file_hash: str):
        return urljoin(
            self.base_url, "v2/inthreat/objects", item_id, "files", file_hash
        )

    def generate_first_cursor(self) -> str:
        """
        Generate the first cursor to interrogate the API
        so we don't start at the beginning.
        """
        start = f"{(datetime.utcnow() - timedelta(hours=1)).isoformat()}Z"
        if self.start_date:
            self.helper.log_info(
                f"Using date provided to the connector: {self.start_date}"
            )
            try:
                start = f"{parse(self.start_date).isoformat()}Z"
            except ParserError:
                self.helper.log_error(
                    f"Impossible to parse the date provided: {self.start_date}. Starting from one hour ago"
                )

        return base64.b64encode(start.encode("utf-8")).decode("utf-8")

    @staticmethod
    def chunks(items, chunk_size):
        """
        Yield successive n-sized chunks from items.
        """
        for i in range(0, len(items), chunk_size):
            yield items[i : i + chunk_size]

    def _run(self, cursor, work_id):

        current_time = f"{datetime.now(timezone.utc).isoformat()}"
        current_cursor = base64.b64encode(current_time.encode("utf-8")).decode("utf-8")

        params = {"limit": self.limit, "cursor": cursor}
        if self.requested_types:
            params["match[type]"] = self.requested_types

        data = self._send_request(self.get_collection_url(), params)
        if not data:
            return cursor

        cursor = data["next_cursor"] or current_cursor  # In case next_cursor is None
        items = data["items"]
        if not items or len(items) == 0:
            return cursor

        items = self._retrieve_references(items)
        self._add_main_observable_type_to_indicators(items)
        if self.create_observables:
            self._add_create_observables_to_indicators(items)
        self._clean_external_references_fields(items)
        items = self._clean_ic_fields(items)
        self._add_files_to_items(items)
        [all_related_objects, all_relationships] = (
            self._retrieve_related_objects_and_relationships(items)
        )

        if self.import_source_list:
            all_related_objects = self._add_sources_to_items(all_related_objects)

        items += all_related_objects + all_relationships
        bundle = self.helper.stix2_create_bundle(items)
        try:
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
        except RecursionError:
            self.helper.log_error(
                "A recursion error occured, circular dependencies detected in the Sekoia bundle, sending the whole "
                "bundle but please fix it "
            )
            self.helper.send_stix2_bundle(bundle, work_id=work_id, bypass_split=True)

        self.helper.set_state({"last_cursor": cursor})
        if len(items) < self.limit:
            # We got the last results
            return cursor

    def _clean_external_references_fields(self, items: List[Dict]):
        """
        Remove empty values from external references and add link to original object in Sekoia.io platform
        """
        for item in items:
            has_sekoia_source = False
            external_references = item.setdefault("external_references", [])
            for ref in external_references:
                if ref.get("source_name") == "Sekoia.io":
                    has_sekoia_source = True
                for key in list(ref.keys()):
                    if not ref[key]:
                        del ref[key]
            if not has_sekoia_source:
                external_references.append(
                    {
                        "source_name": "Sekoia.io",
                        "url": f"https://app.sekoia.io/intelligence/objects/{item['id']}",
                    }
                )

    def _clean_ic_fields(self, items: List[Dict]) -> List[Dict]:
        """
        Remove fields specific to the Intelligence Center
        that will not add value in OpenCTI
        """
        return [
            {
                field: value
                for field, value in item.items()
                if not self._field_to_ignore(field)
            }
            for item in items
        ]

    @staticmethod
    def _field_to_ignore(field: str) -> bool:
        to_ignore = [
            "x_ic_impacted_locations",
            "x_ic_impacted_sectors",
        ]
        return (
            (field.startswith("x_ic") or field.startswith("x_inthreat"))
            and (field.endswith("ref") or field.endswith("refs"))
        ) or field in to_ignore

    def _retrieve_related_objects_and_relationships(self, indicators: List[Dict]):
        all_related_objects = []
        all_relationships = []
        for indicator in indicators:
            indicator_id = indicator["id"]
            if not indicator_id.startswith("indicator--"):
                continue
            try:
                all_data = self._send_request(self.get_relationship(indicator_id))
            except Exception as e:
                self.helper.connector_logger.error(
                    "[ERROR] An error occurred while retrieving related entities for indicator",
                    {"indicator_id": indicator_id, "error": str(e)},
                )
                continue
            if "items" in all_data:
                for data in all_data["items"]:
                    if "related_object" in data:
                        all_related_objects.append(data["related_object"])
                    if "relationship" in data:
                        all_relationships.append(data["relationship"])
            else:
                self.helper.connector_logger.debug(
                    "[DEBUG] No object associated with the indicator",
                    {"indicator_id": indicator_id},
                )

        uniq_related_objects = list(
            {obj["id"]: obj for obj in all_related_objects}.values()
        )

        return [uniq_related_objects, all_relationships]

    @staticmethod
    def _add_create_observables_to_indicators(items: List[Dict]):
        for item in items:
            if item.get("type") == "indicator":
                item["x_opencti_create_observables"] = True

    @staticmethod
    def _add_main_observable_type_to_indicators(items: List[Dict]):
        for item in items:
            if (
                item.get("type") == "indicator"
                and item.get("x_ic_observable_types") is not None
                and len(item.get("x_ic_observable_types")) > 0
            ):
                stix_type = item.get("x_ic_observable_types")[0]
                item["x_opencti_main_observable_type"] = (
                    OpenCTIStix2Utils.stix_observable_opencti_type(stix_type)
                )

    def _retrieve_references(
        self, items: List[Dict], current_depth: int = 0
    ) -> List[Dict]:
        """
        Retrieve the references that appears in the given items.

        To avoid having an infinite recursion a safe guard has been implemented.
        """
        if current_depth == 5:
            # Safeguard to avoid infinite recursion if an object was not found for example
            return items

        items = self._update_mapped_refs(items)
        to_fetch = self._get_missing_refs(items)
        for ref in list(to_fetch):
            if ref in self._cache:
                items.append(self._cache[ref])
                to_fetch.remove(ref)
        if not to_fetch:
            return items

        objects_to_fetch = [i for i in to_fetch if not i.startswith("relationship--")]
        items += self._retrieve_by_ids(objects_to_fetch, self.get_object_url)

        relationships_to_fetch = [i for i in to_fetch if i.startswith("relationship--")]
        items += self._retrieve_by_ids(
            relationships_to_fetch, self.get_relationship_url
        )
        # Avoid circular
        final_items = []
        for item in items:
            if "created_by_ref" in item and item["created_by_ref"] == item["id"]:
                del item["created_by_ref"]
            final_items.append(item)
        return self._retrieve_references(final_items, current_depth + 1)

    def _get_missing_refs(self, items: List[Dict]) -> Set:
        """
        Get the object's references that are missing
        """
        ids = {item["id"] for item in items}
        refs = set()
        for item in items:
            refs.update(item.get("object_marking_refs", []))
            if item.get("created_by_ref"):
                refs.add(item["created_by_ref"])
            if item["type"] == "report":
                object_refs = [
                    ref
                    for ref in item.get("object_refs", [])
                    if not self._is_mapped_ref(ref)
                ]
                refs.update(object_refs)
            if item["type"] == "relationship":
                if not self._is_mapped_ref(item["source_ref"]):
                    refs.add(item["source_ref"])
                if not self._is_mapped_ref(item["target_ref"]):
                    refs.add(item["target_ref"])
        return refs - ids

    def _is_mapped_ref(self, ref: str) -> bool:
        """
        Whether or not the reference is a mapped one.
        """
        return (
            ref in self._geography_mapping.values()
            or ref in self._sectors_mapping.values()
        )

    def _update_mapped_refs(self, items: List[Dict]):
        """
        Update references that are mapped between SEKOIA and OpenCTI.

        This way we will be able to create links with OpenCTI own sectors and locations.
        """
        for item in items:
            if item.get("object_marking_refs"):
                item["object_marking_refs"] = self._replace_mapped_refs(
                    item["object_marking_refs"]
                )
            if item.get("object_refs"):
                item["object_refs"] = self._replace_mapped_refs(item["object_refs"])
            if item.get("source_ref"):
                item["source_ref"] = self._get_mapped_ref(item["source_ref"])
            if item.get("target_ref"):
                item["target_ref"] = self._get_mapped_ref(item["target_ref"])
        return items

    def _replace_mapped_refs(self, refs: List):
        for i, ref in enumerate(refs):
            refs[i] = self._get_mapped_ref(ref)
        return refs

    def _get_mapped_ref(self, ref: str):
        if ref in self._geography_mapping:
            return self._geography_mapping[ref]
        if ref in self._sectors_mapping:
            return self._sectors_mapping[ref]
        return ref

    def _retrieve_by_ids(self, ids, url_callback):
        """
        Fetch the items for the given ids.
        """
        items = []
        for chunk in self.chunks(ids, 40):
            url = url_callback(chunk)
            res = self._send_request(url)
            if not res:
                continue
            if "items" in res:
                items.extend(res["items"])
                for item in res["items"]:
                    self._clean_and_add_to_cache(item)
            if "data" in res:
                items.append(res["data"])
                self._clean_and_add_to_cache(res["data"])
        return items

    def _clean_and_add_to_cache(self, item):
        """
        Add item to the cache only if it is an identity or a marking definition
        """
        if item["id"].startswith("marking-definition--") or item["id"].startswith(
            "identity--"
        ):
            if item["id"].startswith("marking-definition--"):
                item.pop("object_marking_refs", None)
            self._cache[item["id"]] = item

    def _send_request(self, url, params=None, binary=False):
        """
        Sends the HTTP request and handle the errors
        """
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            param_string = (
                "&".join(f"{k}={v}" for k, v in params.items()) if params else ""
            )
            self.helper.log_debug(
                f"Sending request to: {url} with params {param_string}"
            )
            res = requests.get(url, params=params, headers=headers)
            res.raise_for_status()
            if binary:
                return res.content
            return res.json()
        except RequestException as ex:
            if ex.response:
                error = f"Request failed with status: {ex.response.status_code}"
                self.helper.log_error(error)
            else:
                self.helper.log_error(str(ex))
            return None

    def _load_data_sets(self):
        # Mapping between SEKOIA sectors/locations and OpenCTI ones
        ## MODIFICATION BY CYRILYXE
        #   Use of the global variable : gbl_scriptDir
        #   For using absolute path and not relative ones
        global gbl_scriptDir

        self.helper.log_info("Loading locations mapping")
        with open(gbl_scriptDir + "/data/geography_mapping.json") as fp:
            self._geography_mapping: Dict = json.load(fp)

        self.helper.log_info("Loading sectors mapping")
        with open(gbl_scriptDir + "/data/sectors_mapping.json") as fp:
            self._sectors_mapping: Dict = json.load(fp)

        # Adds OpenCTI sectors/locations to cache
        self.helper.log_info("Loading OpenCTI sectors")
        with open(gbl_scriptDir + "/data/sectors.json") as fp:
            objects = json.load(fp)["objects"]
            for sector in objects:
                self._clean_and_add_to_cache(sector)

        self.helper.log_info("Loading OpenCTI locations")
        with open(gbl_scriptDir + "/data/geography.json") as fp:
            for geography in json.load(fp)["objects"]:
                self._clean_and_add_to_cache(geography)

    def _add_files_to_items(self, items: List[Dict]):
        for item in items:
            if not item.get("x_inthreat_uploaded_files"):
                continue
            item["x_opencti_files"] = []
            for file in item.get("x_inthreat_uploaded_files", []):
                url = self.get_file_url(item["id"], file["sha256"])

                if "mime_type" in file and file["mime_type"] == "application/pdf":
                    if "file_name" in file:
                        # Check that the extension exists in the file_name. If not, it will be added.
                        if not os.path.splitext(file["file_name"])[1]:
                            file["file_name"] += ".pdf"

                data = self._send_request(url, binary=True)
                if data:
                    item["x_opencti_files"].append(
                        {
                            "name": file["file_name"],
                            "data": base64.b64encode(data).decode("utf-8"),
                            "mime_type": file.get("mime_type", "text/plain"),
                            "no_trigger_import": True,
                        }
                    )

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
                "[ERROR] The label could not be created. If your connector does not have the permission to create "
                "labels, "
                "please create it manually before launching",
                {"name_label": name_label},
            )
        else:
            self.all_labels.append(new_custom_label["value"])

    def _add_sources_to_items(self, items: List[Dict]):
        object_list = []
        for item in items:

            labels = []
            for source in self._retrieve_by_ids(
                item.get("x_inthreat_sources_refs", []), self.get_object_url
            ):
                label_name = f'source:{source["name"]}'.lower()
                if label_name not in self.all_labels:
                    self._create_custom_label(label_name, "#f8c167")

                labels.append(label_name)

            if labels:
                if item.get("x_opencti_labels", []):
                    item["x_opencti_labels"].extend(labels)
                else:
                    item["x_opencti_labels"] = labels
            object_list.append(item)

        return object_list


if __name__ == "__main__":
    try:
        sekoiaConnector = Sekoia()
        sekoiaConnector.run()
    except Exception as err:
        print(err)
        time.sleep(10)
        sys.exit(0)
