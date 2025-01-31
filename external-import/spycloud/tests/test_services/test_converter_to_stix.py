from datetime import datetime
from unittest.mock import Mock

import pytest
from spycloud_connector.models.spycloud import BreachCatalog, BreachRecord
from spycloud_connector.services import ConverterToStix


@pytest.fixture
def mock_converter_to_stix():
    helper = Mock()
    helper.connect_name = "Spycloud Test"

    config = Mock()
    config.spycloud.tlp_level = "red"

    return ConverterToStix(helper=helper, config=config)


def test_converter_to_stix_author(mock_converter_to_stix):
    # Given a ConverterToStix instance
    # When accessing author attribute
    # Then a valid Author should be returned
    assert mock_converter_to_stix.author.name == "Spycloud Test"
    assert (
        mock_converter_to_stix.author.description
        == "SpyCloud external import connector"
    )
    assert mock_converter_to_stix.author.identity_class == "organization"


def test_converter_to_stix_create_author(mock_converter_to_stix):
    # Given a ConverterToStix instance
    # When calling _create_author
    author = mock_converter_to_stix._create_author(
        name="Test Author",
        description="Test description",
        identity_class="organization",
    )
    # Then a valid Author should be returned
    assert author.name == "Test Author"
    assert author.description == "Test description"
    assert author.identity_class == "organization"


def test_converter_to_stix_create_incident(mock_converter_to_stix):
    # Given a ConverterToStix instance and Spycloud breach catalog + breach record
    breach_catalog = BreachCatalog(
        **{
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
        }
    )
    breach_record = BreachRecord(
        **{
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
        }
    )
    # When calling create_incident
    incident = mock_converter_to_stix.create_incident(
        breach_catalog=breach_catalog,
        breach_record=breach_record,
    )
    # Then a valid Incident should be returned
    assert incident.name is not None
    assert incident.description is not None
    assert incident.author == mock_converter_to_stix.author
    assert incident.created_at == datetime.fromisoformat("2024-12-04T00:00:00Z")
    assert incident.source == "Telegram Combo Cloudxurl"
    assert incident.severity == "high"
    assert incident.incident_type == "data-breach"
    assert incident.first_seen == datetime.fromisoformat("2024-12-04T00:00:00Z")


def test_converter_to_stix_create_observables(mock_converter_to_stix):
    # Given a ConverterToStix instance and Spycloud breach record
    breach_record = BreachRecord(
        **{
            "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
            "source_id": 67701,
            "spycloud_publish_date": "2024-12-04T00:00:00Z",
            "severity": 20,
            "email": "grolfson@example.org",
            "password": "jaXwWsR:v6Tup7.",
            "email_domain": "example.org",
            "email_username": "grolfson",
            "domain": "example.org",
            "password_type": "plaintext",
            "password_plaintext": "jaXwWsR:v6Tup7.",
            "target_url": "http://demo.inertiajs.com/users/3/edit",
            "target_domain": "inertiajs.com",
            "target_subdomain": "demo.inertiajs.com",
            "ip_addresses": ["102.16.50.152"],
            "mac_address": "00:0a:95:9d:68:16",
            "user_os": "Windows 11 build 22631 (64 Bit)",
            "user_hostname": "DESKTOP-QG09M33",
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            "infected_path": "C:\\Users\\LENOVO\\Desktop\\Adobe Illustrator\\Set-up.exe",
            "sighting": 4,
        }
    )

    # When calling create_observables
    observables = mock_converter_to_stix.create_observables(breach_record=breach_record)

    # Then a list of valid Observables should be returned
    assert len(observables) > 0
    assert any(True for observable in observables if observable is None) is False


def test_converter_to_stix_create_directory(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid path
    path = "C:\\Users\\LENOVO\\Desktop\\Adobe Illustrator"

    # When calling _create_directory
    directory = mock_converter_to_stix._create_directory(path=path)

    # Then a valid Directory should be returned
    assert directory.path == path
    assert directory.author == mock_converter_to_stix.author


def test_converter_to_stix_create_directory_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid path
    path = 42

    # When calling _create_directory
    directory = mock_converter_to_stix._create_directory(path=path)

    # Then None should be returned due to validation error
    assert directory is None


def test_converter_to_stix_create_domain_name(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid domain name
    value = "example.org"

    # When calling _create_domain_name
    domain_name = mock_converter_to_stix._create_domain_name(value=value)

    # Then a valid DomainName should be returned
    assert domain_name.value == value
    assert domain_name.author == mock_converter_to_stix.author


def test_converter_to_stix_create_domain_name_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid domain name
    value = "invalid domain name"

    # When calling _create_domain_name
    domain_name = mock_converter_to_stix._create_domain_name(value=value)

    # Then None should be returned due to validation error
    assert domain_name is None


def test_converter_to_stix_create_email_address(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid email address
    value = "test@example.org"
    display_name = "Test User"

    # When calling _create_email_address
    email_address = mock_converter_to_stix._create_email_address(
        value=value, display_name=display_name
    )

    # Then a valid EmailAddress should be returned
    assert email_address.value == value
    assert email_address.display_name == display_name
    assert email_address.author == mock_converter_to_stix.author


def test_converter_to_stix_create_email_address_validation_error(
    mock_converter_to_stix,
):
    # Given a ConverterToStix instance and an invalid email address
    value = "invalid email address"

    # When calling _create_email_address
    email_address = mock_converter_to_stix._create_email_address(value=value)

    # Then None should be returned due to validation error
    assert email_address is None


def test_converter_to_stix_create_file(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid file name
    name = "Set-up.exe"

    # When calling _create_file
    file = mock_converter_to_stix._create_file(name=name)

    # Then a valid File should be returned
    assert file.name == name
    assert file.author == mock_converter_to_stix.author


def test_converter_to_stix_create_file_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid file name
    name = 42

    # When calling _create_file
    file = mock_converter_to_stix._create_file(name=name)

    # Then None should be returned due to validation error
    assert file is None


def test_converter_to_stix_create_ip_address(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid IPv4 address
    value = "192.168.1.1"

    # When calling _create_ip_address
    ip_address = mock_converter_to_stix._create_ip_address(value=value)

    # Then a valid IPv4Address should be returned
    assert ip_address.value == value
    assert ip_address.author == mock_converter_to_stix.author


def test_converter_to_stix_create_ip_address_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid IP address
    value = "invalid_ip"

    # When calling _create_ip_address
    ip_address = mock_converter_to_stix._create_ip_address(value=value)

    # Then None should be returned due to validation error
    assert ip_address is None


def test_converter_to_stix_create_mac_address(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid MAC address
    value = "00:0a:95:9d:68:16"

    # When calling _create_mac_address
    mac_address = mock_converter_to_stix._create_mac_address(value=value)

    # Then a valid MACAddress should be returned
    assert mac_address.value == value
    assert mac_address.author == mock_converter_to_stix.author


def test_converter_to_stix_create_mac_address_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid MAC address
    value = "invalid_mac_address"

    # When calling _create_mac_address
    mac_address = mock_converter_to_stix._create_mac_address(value=value)

    # Then None should be returned due to validation error
    assert mac_address is None


def test_converter_to_stix_create_url(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid URL
    value = "http://example.org"

    # When calling _create_url
    url = mock_converter_to_stix._create_url(value=value)

    # Then a valid URL should be returned
    assert url.value == value
    assert url.author == mock_converter_to_stix.author


def test_converter_to_stix_create_url_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid URL
    value = 42

    # When calling _create_url
    url = mock_converter_to_stix._create_url(value=value)

    # Then None should be returned due to validation error
    assert url is None


def test_converter_to_stix_create_user_account(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid user account
    account_login = "test_user"
    account_type = "Windows"

    # When calling _create_user_account
    user_account = mock_converter_to_stix._create_user_account(
        account_login=account_login, account_type=account_type
    )

    # Then a valid UserAccount should be returned
    assert user_account.account_login == account_login
    assert user_account.account_type == account_type
    assert user_account.author == mock_converter_to_stix.author


def test_converter_to_stix_create_user_account_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid user account
    account_login = 42

    # When calling _create_user_account
    user_account = mock_converter_to_stix._create_user_account(
        account_login=account_login
    )

    # Then None should be returned due to validation error
    assert user_account is None


def test_converter_to_stix_create_user_agent(mock_converter_to_stix):
    # Given a ConverterToStix instance and a valid user agent
    value = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X)"

    # When calling _create_user_agent
    user_agent = mock_converter_to_stix._create_user_agent(value=value)

    # Then a valid UserAgent should be returned
    assert user_agent.value == value
    assert user_agent.author == mock_converter_to_stix.author


def test_converter_to_stix_create_user_agent_validation_error(mock_converter_to_stix):
    # Given a ConverterToStix instance and an invalid user agent
    value = 42

    # When calling _create_user_agent
    user_agent = mock_converter_to_stix._create_user_agent(value=value)

    # Then None should be returned due to validation error
    assert user_agent is None
