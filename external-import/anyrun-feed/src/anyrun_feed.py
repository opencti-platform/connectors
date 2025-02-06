import json
import os
import sys
import time

import requests
from lib.external_import import ExternalImportConnector


class AnyrunFeed(ExternalImportConnector):
    def __init__(self):
        super().__init__()
        self.token = os.environ.get("ANYRUN_TI_TOKEN", "")
        self.ti_url = os.environ.get("ANYRUN_TI_URL", "https://api.any.run/v1/feeds/stix.json")

    def get_feed(self):
        response = requests.get(
            self.ti_url, headers={"Authorization": "API-Key {}".format(self.token)}
        )
        if response.status_code == 401:
            response = requests.get(
                self.ti_url, headers={"Authorization": "Basic {}".format(self.token)}
            )
        if response.status_code != 200:
            raise ValueError(
                "Any.RUN api code {}. text: {}".format(
                    response.status_code, response.text
                )
            )
        return json.loads(response.text)

    def _collect_intelligence(self) -> []:
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        feed = self.get_feed()

        stix_objects = feed["data"]["objects"]

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = AnyrunFeed()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
