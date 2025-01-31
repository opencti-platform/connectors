from datetime import datetime

import pytest
from pydantic import ValidationError
from spycloud_connector.models.opencti import (
    Author,
    EmailAddress,
    Incident,
    RelatedTo,
    TLPMarking,
)


def mock_valid_author():
    return Author(name="Valid Author", identity_class="organization")


def mock_valid_markings():
    return [TLPMarking(level="red")]


def mock_valid_email_observable():
    return EmailAddress(
        value="username@example.com",
        author=mock_valid_author(),
        markings=mock_valid_markings(),
    )


def mock_valid_incident():
    return Incident(
        name="Valid Incident",
        author=mock_valid_author(),
        created_at=datetime(1970, 1, 1),
        markings=mock_valid_markings(),
        source="Unknown",
        severity="low",
        incident_type="data-breach",
        first_seen=datetime(1970, 1, 1),
    )


# Valid Input Tests
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "description": "Relationship Description",
                "source": mock_valid_email_observable(),
                "target": mock_valid_incident(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "source": mock_valid_email_observable(),
                "target": mock_valid_incident(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_related_to_class_should_accept_valid_input(input_data):
    # Given: valid input data for the RelatedTo class
    input_data_dict = dict(input_data)

    # When: we create a RelatedTo instance
    relationship = RelatedTo(**input_data_dict)

    # Then: the RelatedTo instance should be created successfully
    assert relationship._relationship_type == "related-to"
    assert relationship.description == input_data_dict.get("description")
    assert relationship.source == input_data_dict.get("source")
    assert relationship.target == input_data_dict.get("target")
    assert relationship.author == input_data_dict.get("author")
    assert relationship.created_at == input_data_dict.get("created_at")
    assert relationship.modified_at == input_data_dict.get("modified_at")
    assert relationship.markings == input_data_dict.get("markings")
    assert (
        relationship.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Tests
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "target": mock_valid_incident(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            "source",
            id="invalid_missing_source",
        ),
        pytest.param(
            {
                "source": mock_valid_email_observable(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            "target",
            id="invalid_missing_target",
        ),
        pytest.param(
            {
                "source": mock_valid_incident(),
                "target": mock_valid_incident(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            "source",
            id="invalid_source_type",
        ),
        pytest.param(
            {
                "source": mock_valid_email_observable(),
                "target": mock_valid_email_observable(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
            },
            "target",
            id="invalid_target_type",
        ),
        pytest.param(
            {
                "source": mock_valid_email_observable(),
                "target": mock_valid_incident(),
                "author": mock_valid_author(),
                "created_at": datetime(1970, 1, 1),
                "modified_at": datetime(1970, 1, 1),
                "markings": mock_valid_markings(),
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_related_to_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: invalid input data for the RelatedTo class
    input_data_dict = dict(input_data)

    # When: we try to create a RelatedTo instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        RelatedTo(**input_data_dict)
    assert str(error_field) in str(err)
