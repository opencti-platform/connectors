import pytest
from pydantic import ValidationError
from spycloud_connector.models.opencti import Author, TLPMarking


# Valid Input Test
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Author Name",
                "description": "A description of the author.",
                "identity_class": "organization",
            },
            id="full_valid_data",
        ),
        pytest.param(
            {"name": "Minimal Author", "identity_class": "organization"},
            id="minimal_valid_data",
        ),
    ],
)
def test_author_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dict = dict(input_data)

    # When: We create an Author instance with valid input data
    author = Author(**input_data_dict)

    # Then: The Author instance should be created successfully
    assert author.name == input_data_dict.get("name")
    assert author.description == input_data_dict.get("description")
    assert (
        author.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Test
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {"description": "Missing name field", "identity_class": "organization"},
            "name",
            id="missing_name_field",
        ),
        pytest.param(
            {
                "name": ["Author Name"],
                "description": "A description of the author.",
                "identity_class": "organization",
            },
            "name",
            id="invalid_name_type",
        ),
        pytest.param(
            {
                "name": "Author Name",
                "identity_class": "organization",
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_author_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input params
    input_data_dict = dict(input_data)

    # When: We try to create an Author instance with invalid data
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        Author(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Test for TLPMarking
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "level": "white",
            },
            id="full_valid_data",
        ),
        pytest.param(
            {"level": "green"},
            id="minimal_valid_data",
        ),
    ],
)
def test_tlp_marking_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dict = dict(input_data)

    # When: We create a TLPMarking instance with valid input data
    tlp_marking = TLPMarking(**input_data_dict)

    # Then: The TLPMarking instance should be created successfully
    assert tlp_marking.level == input_data_dict.get("level")
    assert (
        tlp_marking.to_stix2_object() is not None
    )  # Ensure the STIX2 object generation works


# Invalid Input Test for TLPMarking
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {},
            "level",
            id="missing_level_field",
        ),
        pytest.param(
            {
                "level": ["white"],
            },
            "level",
            id="invalid_level_type",
        ),
        pytest.param(
            {
                "level": "white",
                "extra_field": "extra_value",
            },
            "extra_field",
            id="invalid_extra_field",
        ),
    ],
)
def test_tlp_marking_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input params
    input_data_dict = dict(input_data)

    # When: We try to create a TLPMarking instance with invalid data
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        TLPMarking(**input_data_dict)
    assert str(error_field) in str(err)
