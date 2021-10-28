# This is just the defaults as a Python dict. Please override any settings in a `config.yml`
defaults: dict = {
    "opencti": {
        "ssl_verify": True,
        "token": None,
        "url": "http://localhost:8080",
    },
    "connector": {
        "id": None,
        "type": "EXTERNAL_IMPORT",
        "name": "SethSites OpenCTI Connector",
        "scope": "identity,attack-pattern,course-of-action,intrusion-set,tool,report,malware,location",
        "confidence_level": 80,
        "log_level": "INFO",
        "entity_description": "Elastic detection engine results via connector",
        "entity_name": "Elastic CTI Cluster",
        "reload_environment": False,
        "interval": 300
    },
    "client": {
        "name": "",
        "cloud": {"auth": None, "id": None},
        "elasticsearch": {
            "hosts": ["localhost:9200"],
            "ssl_verify": True,
            "username": None,
            "password": None,
            "api_key": None
        }
    },
    "scanner": {
        "ping": {
            "time_sensitivity": 300,
            "target_sensitivity": 2
        }
    }
}
