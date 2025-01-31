import requests


class ConnectorClient:
    """
    Represents the methods required for the Bambenek client interface.
    """

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.base_url = "https://faf.bambenekconsulting.com/feeds/"
        self.auth = (self.config.bambenek_username, self.config.bambenek_password)
        self.session = requests.Session()
        self.collection_url = {
            "c2_dga": "dga/dga-feed.csv",
            "c2_dga_high_conf": "dga/dga-feed-high.csv",
            "c2_domain": "dga/c2-dommasterlist.txt",
            "c2_domain_highconf": "dga/c2-dommasterlist-high.txt",
            "c2_ip": "dga/c2-ipmasterlist.txt",
            "c2_ip_highconf": "dga/c2-ipmasterlist-high.txt",
            "c2_masterlist": "dga/c2-masterlist.txt",
            "sinkhole": "sinkhole/latest.csv",  # Sinkhole feed is only updated once a day
        }

    def get_collections_entities(self, collection):
        """
        Downloads the whole file from the Bambenek URL. The entities will be CSV strings, some have pipe-limited values
        within the csv fields
        """
        collection_path = self.collection_url.get(collection)
        collection_api_url = self.base_url + collection_path
        response = self.session.get(url=collection_api_url, auth=self.auth)
        response.raise_for_status()
        resp_ascii = str(response.content, "ascii").split("\n")
        # All the bambenek files have a large number of comment lines at the top. This filters those out
        filtered_entries = [entry for entry in resp_ascii if not entry.startswith("#")]
        return filtered_entries
