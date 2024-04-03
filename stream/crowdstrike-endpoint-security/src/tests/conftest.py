import json
import os
from unittest.mock import Mock

import pytest
import requests
from connector import CrowdstrikeConnector
from services.client import CrowdstrikeClient


@pytest.fixture(autouse=True)
def disable_network_calls(monkeypatch):
    """
    Make a fixture available for whole project without having to import it
    Ensure that network calls will be disabled in every test across the suite
    Adding scope="session" will execute only once per whole test run
    :param monkeypatch:
    :return:
    """

    def stunted_get():
        raise RuntimeError("Network access not allowed during testing!")

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: stunted_get())


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = Mock()
    request.cls.mock_client = CrowdstrikeClient(request.cls.mock_helper)
    request.cls.connector = CrowdstrikeConnector()
    request.cls.connector.helper = request.cls.mock_helper

    yield
    print("Teardown configuration")


@pytest.fixture(scope="class")
def stream_event(request):
    request.cls.ioc_event_create = load_file("event_create_indicator_sample.json")
    request.cls.ioc_event_update = load_file("event_update_indicator_sample.json")
    request.cls.ioc_event_delete = load_file("event_delete_indicator_sample.json")


@pytest.fixture(scope="class")
def api_response(request):
    request.cls.res_file_hash = load_file("response_file_hash_sample.json")


def load_file(filename: str) -> dict:
    """
    Utility function to load a json file to a dict
    :param filename: Filename in string
    :return:
    """
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)
