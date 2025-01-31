from datetime import datetime

import pytest
from pydantic import ValidationError
from spycloud_connector.models.spycloud import BreachCatalog, BreachRecord


# Valid Input Test
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                # Required fields
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
                # Optional fields
                "combo_list_flag": "YES",
                "site_description": "This PII data allegedly belongs to individuals/consumers based in an unknown country.",
                "site": "n/a",
            },
            id="valid_full_data",
        ),
        pytest.param(
            {
                # Required fields
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            id="valid_minimal_data",
        ),
    ],
)
def test_breach_catalog_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dict = dict(input_data)

    # When: We create an BreachCatalog instance with valid input data
    breach_catalog = BreachCatalog(**input_data_dict)

    # Then: The BreachCatalog instance should be created successfully
    # Required fields should be present
    assert breach_catalog.id == input_data_dict.get("id")
    assert breach_catalog.uuid == input_data_dict.get("uuid")
    assert breach_catalog.title == input_data_dict.get("title")
    assert breach_catalog.description == input_data_dict.get("description")
    assert breach_catalog.type == input_data_dict.get("type")
    assert breach_catalog.num_records == input_data_dict.get("num_records")
    assert breach_catalog.spycloud_publish_date == datetime.fromisoformat(
        input_data_dict.get("spycloud_publish_date")
    )
    assert breach_catalog.acquisition_date == datetime.fromisoformat(
        input_data_dict.get("acquisition_date")
    )
    assert breach_catalog.assets == input_data_dict.get("assets")
    assert breach_catalog.confidence == input_data_dict.get("confidence")
    assert breach_catalog.breach_main_category == input_data_dict.get(
        "breach_main_category"
    )
    assert breach_catalog.breach_category == input_data_dict.get("breach_category")
    assert breach_catalog.sensitive_source == input_data_dict.get("sensitive_source")
    assert breach_catalog.consumer_category == input_data_dict.get("consumer_category")
    assert breach_catalog.tlp == input_data_dict.get("tlp")
    assert breach_catalog.short_title == input_data_dict.get("short_title")
    # Optional fields should be ignored
    assert hasattr(breach_catalog, "combo_list_flag") is False
    assert hasattr(breach_catalog, "site_description") is False
    assert hasattr(breach_catalog, "site") is False


# Invalid Input Test
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            "title",
            id="missing_title_field",
        ),
        pytest.param(
            {
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 150,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            "confidence",
            id="invalid_confidence_value",
        ),
        pytest.param(
            {
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "public",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            "type",
            id="invalid_type_case",
        ),
        pytest.param(
            {
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": [
                    ("target_url", 223282538),
                    ("salt", 90),
                    ("username", 135505898),
                    ("password", 231369461),
                    ("email", 98941453),
                ],
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            "assets",
            id="invalid_assets_type",
        ),
        pytest.param(
            {
                "id": 67701,
                "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
                "title": "Telegram Combo Cloudxurl",
                "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
                "type": "PUBLIC",
                "num_records": 234444786,
                "spycloud_publish_date": "04/12/2024",
                "acquisition_date": "2024-11-22T00:00:00Z",
                "assets": {
                    "target_url": 223282538,
                    "salt": 90,
                    "username": 135505898,
                    "password": 231369461,
                    "email": 98941453,
                },
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "exfiltrated",
                "sensitive_source": False,
                "consumer_category": "publicexposure",
                "tlp": "amber",
                "short_title": "Telegram Combo Cloudxurl",
            },
            "spycloud_publish_date",
            id="invalid_spycloud_publish_date_format",
        ),
    ],
)
def test_breach_catalog_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: Invalid input params
    input_data_dict = dict(input_data)

    # When: We try to create an BreachCatalog instance with invalid data
    # Then: A ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        BreachCatalog(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Test
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                # Required fields
                "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
                "source_id": 67701,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "severity": 20,
                # Optional fields
                "email": "grolfson@example.org",
                "password": "jaXwWsR:v6Tup7.",
                "target_url": "http://demo.inertiajs.com/users/3/edit",
                "email_domain": "example.org",
                "email_username": "grolfson",
                "domain": "example.org",
                "target_domain": "inertiajs.com",
                "target_subdomain": "demo.inertiajs.com",
                "password_type": "plaintext",
                "password_plaintext": "jaXwWsR:v6Tup7.",
                "sighting": 4,
            },
            id="valid_full_data",
        ),
        pytest.param(
            {
                # Required fields
                "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
                "source_id": 67701,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "severity": 20,
            },
            id="valid_minimal_data",
        ),
    ],
)
def test_breach_record_class_should_accept_valid_input(input_data):
    # Given: Valid input params
    input_data_dict = dict(input_data)

    # When: We create an BreachRecord instance with valid input data
    breach_record = BreachRecord(**input_data_dict)

    # Then: The BreachRecord instance should be created successfully
    # Required fields should be present
    assert breach_record.document_id == input_data_dict.get("document_id")
    assert breach_record.source_id == input_data_dict.get("source_id")
    assert breach_record.spycloud_publish_date == datetime.fromisoformat(
        input_data_dict.get("spycloud_publish_date")
    )
    assert breach_record.severity == input_data_dict.get("severity")
    # Optional fields should be allowed
    assert hasattr(breach_record, "email") is not None
    assert hasattr(breach_record, "password") is not None
    assert hasattr(breach_record, "target_url") is not None


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "severity": 20,
            },
            "source_id",
            id="invalid_missing_source_id",
        ),
        pytest.param(
            {
                "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
                "source_id": 67701,
                "spycloud_publish_date": "2024-12-04T00:00:00Z",
                "severity": 42,
            },
            "severity",
            id="invalid_severity_value",
        ),
        pytest.param(
            {
                "document_id": ["0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f"],
                "source_id": 67701,
                "spycloud_publish_date": "04/12/2024",
                "severity": 20,
            },
            "document_id",
            id="invalid_document_id_type",
        ),
        pytest.param(
            {
                "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
                "source_id": 67701,
                "spycloud_publish_date": "04/12/2024",
                "severity": 20,
            },
            "spycloud_publish_date",
            id="invalid_spycloud_publish_date_format",
        ),
    ],
)
def test_breach_record_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: invalid input data for the Vulnerability class
    input_data_dct = dict(input_data)

    # When: we try to create a Vulnerability instance
    # Then: a ValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ValidationError) as err:
        BreachRecord(**input_data_dct)
    assert str(error_field) in str(err)
