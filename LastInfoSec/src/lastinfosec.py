import traceback
import os
import yaml
import time
import requests
import json

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIApiClient


class LastInfoSec:
    def __init__(self):
        config_file_path = os.path.dirname(
            os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.lastinfosec_url = get_config_variable(
            "CONFIG_LIS_URL", ["config", "lastinfosec_url"], config)
        self.lastinfosec_apikey = get_config_variable(
            "CONFIG_LIS_APIKEY", ["config", "lastinfosec_apikey"], config)
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config)
        self.opencti_id = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config)

        self.update_existing_data = True
        self.api = OpenCTIApiClient(self.opencti_url, self.opencti_id)

    def run(self):
        self.helper.log_info("Fetching LastInfoSec datasets...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: {0}".format(datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")))
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                lastinfosec_data = requests.get(
                    self.lastinfosec_url+self.lastinfosec_apikey).json()
                if "message" in lastinfosec_data.keys():
                    for data in lastinfosec_data["message"]:
                        sdata = json.dumps(data)
                        self.helper.log_info(type(sdata))
                        self.helper.log_info(sdata)
                        list = self.api.stix2.import_bundle_from_json(sdata)
                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as {0}".format(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    time.sleep(3500)
                else:
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as {0}".format(timestamp)
                    )
                    time.sleep(300)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error("run:"+str(e))
                traceback.print_exc()
                time.sleep(60)


if __name__ == "__main__":
    try:
        lastInfoSecConnector = LastInfoSec()
        lastInfoSecConnector.run()
    except Exception as e:
        traceback.print_exc()
        time.sleep(10)
        exit(0)
