from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth


class ElasticsearchManager:
    """Manages Elasticsearch querying and pagination."""

    def __init__(self, elasticsearch_host, username, password, helper):
        self.elasticsearch_host = elasticsearch_host
        self.username = username
        self.password = password
        self.helper = helper

    def query_with_pagination(self, last_run, now):
        """Query Elasticsearch with pagination, limited to data since the last run."""
        self.helper.log_info("Starting paginated query in Elasticsearch.")
        all_hits = []
        from_param = 0
        size_param = 1000
        total_hits = 1

        while from_param < total_hits:
            search_source_json = self.construct_query(
                last_run, now, from_param, size_param
            )
            es_url = f"{self.elasticsearch_host}/_search"
            es_response = requests.post(
                es_url,
                json=search_source_json,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,
            )

            if es_response.status_code == 200:
                response_json = es_response.json()
                hits = response_json.get("hits", {}).get("hits", [])
                all_hits.extend(hits)
                total_hits = (
                    response_json.get("hits", {}).get("total", {}).get("value", 0)
                )
                from_param += size_param
                self.helper.log_info(
                    f"Retrieved {len(hits)} hits, total hits so far: {len(all_hits)}"
                )
            elif es_response.status_code == 401:
                self.helper.log_error("Authentication error querying Elasticsearch.")
                break
            else:
                self.helper.log_error(
                    f"Error querying Elasticsearch: {es_response.status_code}"
                )
                self.helper.log_error(es_response.text)
                break

        return all_hits

    def construct_query(self, last_run, now, from_param=0, size_param=1000):
        """Construct the Elasticsearch query to fetch data since the last run."""
        if isinstance(last_run, datetime):
            last_run = last_run.isoformat()
        now_iso = now.isoformat()

        search_source_json = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": last_run,
                                    "lte": now_iso,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                        {
                            "query_string": {
                                "query": 'ip_rep: "known attacker"',
                                "default_field": "*",
                            }
                        },
                        {"exists": {"field": "src_ip"}},
                        {"exists": {"field": "input"}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": from_param,
            "size": size_param,
        }
        self.helper.log_info(
            f"Constructed query from {last_run} to {now_iso} with size {size_param}"
        )
        return search_source_json
