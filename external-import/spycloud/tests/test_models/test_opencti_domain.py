from datetime import datetime

import pytest
from pydantic import ValidationError
from spycloud_connector.models.opencti import Author, Incident, TLPMarking


def mock_valid_author():
    return Author(name="Valid Author", identity_class="organization")


def mock_valid_markings():
    return [TLPMarking(level="red")]


# Valid Input Tests
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Valid Incident",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_incident_class_should_accept_valid_input(input_data):
    # Given: valid input data for the Incident class
    input_data_dict = dict(input_data)
    # When: we create a Incident instance
    incident = Incident(**input_data_dict)

    # Then: the Incident instance should be created successfully
    assert incident.name == input_data_dict["name"]
    assert incident.description == input_data_dict.get("description")
    assert incident.author == input_data_dict.get("author")
    assert incident.created_at == input_data_dict.get("created_at")
    assert incident.updated_at == input_data_dict.get("updated_at")
    assert incident.markings == input_data_dict.get("markings")
    assert (
        incident.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Tests
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Incident description",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            "name",
            id="invalid_missing_name",
        ),
        pytest.param(
            {
                "name": "",
                "description": "Incident description",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            "name",
            id="invalid_empty_name",
        ),
        pytest.param(
            {
                "name": "Incident name",
                "description": "Incident description",
                "author": "Invalid author",
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            "author",
            id="invalid_author_type",
        ),
        pytest.param(
            {
                "name": "Incident name",
                "description": "Incident description",
                "author": mock_valid_author(),
                "created_at": "01/01/1970",
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            "created_at",
            id="invalid_date_format",
        ),
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "invalid value",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
            },
            "severity",
            id="invalid_severity_value",
        ),
        pytest.param(
            {
                "name": "Incident with Author",
                "description": "Incident Description",
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "source": "Unknown",
                "severity": "low",
                "incident_type": "data-breach",
                "first_seen": datetime(1970, 1, 1),
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_incident_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the Incident class
    input_data_dict = dict(input_data)

    # When: we try to create a Incident instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Incident(**input_data_dict)
    assert str(error_field) in str(err)
