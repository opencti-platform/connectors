import builtins
import json
import os
import sys
import time
from datetime import datetime

import requests
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable


class ThreatMatch:
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
        self.threatmatch_url = get_config_variable(
            "THREATMATCH_URL", ["threatmatch", "url"], config
        )
        self.threatmatch_client_id = get_config_variable(
            "THREATMATCH_CLIENT_ID", ["threatmatch", "client_id"], config
        )
        self.threatmatch_client_secret = get_config_variable(
            "THREATMATCH_CLIENT_SECRET", ["threatmatch", "client_secret"], config
        )
        self.threatmatch_interval = get_config_variable(
            "THREATMATCH_INTERVAL", ["threatmatch", "interval"], config, True, 5
        )
        self.threatmatch_import_from_date = get_config_variable(
            "THREATMATCH_IMPORT_FROM_DATE", ["threatmatch", "import_from_date"], config
        )
        self.threatmatch_import_profiles = get_config_variable(
            "THREATMATCH_IMPORT_PROFILES",
            ["threatmatch", "import_profiles"],
            config,
            False,
            True,
        )
        self.threatmatch_import_alerts = get_config_variable(
            "THREATMATCH_IMPORT_ALERTS",
            ["threatmatch", "import_alerts"],
            config,
            False,
            True,
        )
        self.threatmatch_import_iocs = get_config_variable(
            "THREATMATCH_IMPORT_IOCS",
            ["threatmatch", "import_iocs"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Security Alliance",
            description="Security Alliance is a cyber threat intelligence product and services company, formed in 2007.",
        )

    def get_interval(self):
        return int(self.threatmatch_interval) * 60

    def next_run(self, seconds):
        return

    def _get_token(self):
        r = requests.post(
            self.threatmatch_url + "/api/developers-platform/token",
            json={
                "client_id": self.threatmatch_client_id,
                "client_secret": self.threatmatch_client_secret,
            },
        )
        if r.status_code != 200:
            raise ValueError("ThreatMatch Authentication failed")
        data = r.json()
        return data.get("access_token")

    def _get_item(self, token, type, item_id):
        headers = {"Authorization": "Bearer " + token}
        r = requests.get(
            self.threatmatch_url + "/api/stix/" + type + "/" + str(item_id),
            headers=headers,
        )
        if r.status_code != 200:
            self.helper.log_error(str(r.text))
            return []
        if r.status_code == 200:
            data = r.json()["objects"]
            for object in data:
                object["description"] = BeautifulSoup(
                    object["description"], "html.parser"
                ).get_text()
            return data

    def _process_list(self, work_id, token, type, list):
        if len(list) > 0:
            if builtins.type(list[0]) is dict:
                bundle = list
                self._process_bundle(work_id, bundle)
            else:
                for item in list:
                    bundle = self._get_item(token, type, item)
                    self._process_bundle(work_id, bundle)

    def _process_bundle(self, work_id, bundle):
        if len(bundle) > 0:
            final_objects = []
            for stix_object in bundle:
                if "error" in stix_object:
                    continue
                if "created_by_ref" not in stix_object:
                    stix_object["created_by_ref"] = self.identity["standard_id"]
                if "object_refs" in stix_object and stix_object["type"] not in [
                    "report",
                    "note",
                    "opinion",
                    "observed-data",
                ]:
                    del stix_object["object_refs"]
                    pass
                final_objects.append(stix_object)
                final_bundle = {"type": "bundle", "objects": final_objects}
                final_bundle_json = json.dumps(final_bundle)
                self.helper.send_stix2_bundle(
                    final_bundle_json,
                    work_id=work_id,
                    update=self.update_existing_data,
                )

    def run(self):
        self.helper.log_info("Fetching ThreatMatch...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.threatmatch_interval) - 1) * 60)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "ThreatMatch run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        token = self._get_token()
                        import_from_date = "2010-01-01 00:00"
                        if last_run is not None:
                            import_from_date = datetime.utcfromtimestamp(
                                last_run
                            ).strftime("%Y-%m-%d %H:%M")
                        elif self.threatmatch_import_from_date is not None:
                            import_from_date = self.threatmatch_import_from_date

                        headers = {"Authorization": "Bearer " + token}
                        if self.threatmatch_import_profiles:
                            r = requests.get(
                                self.threatmatch_url + "/api/profiles/all",
                                headers=headers,
                                json={
                                    "mode": "compact",
                                    "date_since": import_from_date,
                                },
                            )
                            if r.status_code != 200:
                                self.helper.log_error(str(r.text))
                            data = r.json()
                            self._process_list(
                                work_id, token, "profiles", data.get("list")
                            )
                        if self.threatmatch_import_alerts:
                            r = requests.get(
                                self.threatmatch_url + "/api/alerts/all",
                                headers=headers,
                                json={
                                    "mode": "compact",
                                    "date_since": import_from_date,
                                },
                            )
                            if r.status_code != 200:
                                self.helper.log_error(str(r.text))
                            data = r.json()
                            self._process_list(
                                work_id, token, "alerts", data.get("list")
                            )
                        if self.threatmatch_import_iocs:
                            response = requests.get(
                                self.threatmatch_url + "/api/taxii/groups",
                                headers=headers,
                            ).json()
                            all_results_id = response[0]["id"]
                            date = datetime.strptime(import_from_date, "%Y-%m-%d %H:%M")
                            date = date.isoformat(timespec="milliseconds") + "Z"
                            params = {
                                "groupId": all_results_id,
                                "stixTypeName": "indicator",
                                "modifiedAfter": date,
                            }
                            r = requests.get(
                                self.threatmatch_url + "/api/taxii/objects",
                                headers=headers,
                                params=params,
                            )
                            if r.status_code != 200:
                                self.helper.log_error(str(r.text))
                            more = r.json()["more"]
                            if not more:
                                data = r.json()["objects"]
                            else:
                                data = []
                            # This bit is necessary to load all the indicators to upload by checking by date
                            while more:
                                params["modifiedAfter"] = date
                                r = requests.get(
                                    self.threatmatch_url + "/api/taxii/objects",
                                    headers=headers,
                                    params=params,
                                )
                                if r.status_code != 200:
                                    self.helper.log_error(str(r.text))
                                data.extend(r.json().get("objects", []))
                                date = r.json()["objects"][-1]["modified"]
                                more = r.json().get("more", False)
                            self.helper.log_info(data)
                            self._process_list(work_id, token, "indicators", data)
                    except Exception as e:
                        self.helper.log_error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60, 2))
                        + " minutes"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        threatMatchConnector = ThreatMatch()
        threatMatchConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
