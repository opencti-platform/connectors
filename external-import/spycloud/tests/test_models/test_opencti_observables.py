import pytest
from pydantic import ValidationError
from spycloud_connector.models.opencti import (
    URL,
    Author,
    Directory,
    DomainName,
    EmailAddress,
    File,
    IPv4Address,
    IPv6Address,
    MACAddress,
    TLPMarking,
    UserAccount,
    UserAgent,
)


def mock_valid_author():
    return Author(name="Valid Author", identity_class="organization")


def mock_valid_markings():
    return [TLPMarking(level="white")]


# Valid Input Tests for Directory
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "path": "c:/example",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_directory_class_should_accept_valid_input(input_data):
    # Given: valid input data for the Directory class
    input_data_dict = dict(input_data)
    # When: we create a Directory instance
    domain_name = Directory(**input_data_dict)

    # Then: the Directory instance should be created successfully
    assert domain_name.path == input_data_dict.get("path")
    assert domain_name.author == input_data_dict.get("author")
    assert domain_name.markings == input_data_dict.get("markings", [])
    assert domain_name.to_stix2_object() is not None


# Invalid Input Tests for Directory
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "path",
            id="missing_path_field",
        ),
        pytest.param(
            {
                "path": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "path",
            id="empty_path_field",
        ),
    ],
)
def test_directory_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the Directory class
    input_data_dict = dict(input_data)

    # When: we try to create a Directory instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        Directory(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for DomainName
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "example.com",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_domain_name_class_should_accept_valid_input(input_data):
    # Given: valid input data for the DomainName class
    input_data_dict = dict(input_data)
    # When: we create a DomainName instance
    domain_name = DomainName(**input_data_dict)

    # Then: the DomainName instance should be created successfully
    assert domain_name.value == input_data_dict.get("value")
    assert domain_name.author == input_data_dict.get("author")
    assert domain_name.markings == input_data_dict.get("markings", [])
    assert domain_name.to_stix2_object() is not None


# Invalid Input Tests for DomainName
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
    ],
)
def test_domain_name_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the DomainName class
    input_data_dict = dict(input_data)

    # When: we try to create a DomainName instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        DomainName(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for EmailAddress
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "user@example.com",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_email_address_class_should_accept_valid_input(input_data):
    # Given: valid input data for the EmailAddress class
    input_data_dict = dict(input_data)
    # When: we create a EmailAddress instance
    email_address = EmailAddress(**input_data_dict)

    # Then: the EmailAddress instance should be created successfully
    assert email_address.value == input_data_dict.get("value")
    assert email_address.author == input_data_dict.get("author")
    assert email_address.markings == input_data_dict.get("markings", [])
    assert email_address.to_stix2_object() is not None


# Invalid Input Tests for EmailAddress
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
        pytest.param(
            {
                "value": "invalid_email",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="invalid_email_format",
        ),
    ],
)
def test_email_address_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the EmailAddress class
    input_data_dict = dict(input_data)

    # When: we try to create a EmailAddress instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        EmailAddress(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for File
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "example.txt",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_file_class_should_accept_valid_input(input_data):
    # Given: valid input data for the File class
    input_data_dict = dict(input_data)
    # When: we create a File instance
    file = File(**input_data_dict)

    # Then: the File instance should be created successfully
    assert file.name == input_data_dict.get("name")
    assert file.author == input_data_dict.get("author")
    assert file.markings == input_data_dict.get("markings", [])
    assert file.to_stix2_object() is not None


# Invalid Input Tests for File
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "name",
            id="missing_name_field",
        ),
        pytest.param(
            {
                "name": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "name",
            id="empty_name_field",
        ),
    ],
)
def test_file_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the File class
    input_data_dict = dict(input_data)

    # When: we try to create a File instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        File(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for IPv4Address
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "192.168.0.1",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_ipv4address_class_should_accept_valid_input(input_data):
    # Given: valid input data for the IPv4Address class
    input_data_dict = dict(input_data)
    # When: we create a IPv4Address instance
    ipv4_address = IPv4Address(**input_data_dict)

    # Then: the IPv4Address instance should be created successfully
    assert ipv4_address.value == input_data_dict.get("value")
    assert ipv4_address.author == input_data_dict.get("author")
    assert ipv4_address.markings == input_data_dict.get("markings", [])
    assert ipv4_address.to_stix2_object() is not None


# Invalid Input Tests for IPv4Address
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
        pytest.param(
            {
                "value": "XXX.XXX.X.X",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="invalid_ip_format",
        ),
    ],
)
def test_ipv4address_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the IPv4Address class
    input_data_dict = dict(input_data)

    # When: we try to create a IPv4Address instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        IPv4Address(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for IPv6Address
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_ipv6address_class_should_accept_valid_input(input_data):
    # Given: valid input data for the IPv6Address class
    input_data_dict = dict(input_data)
    # When: we create a IPv6Address instance
    ipv6_address = IPv6Address(**input_data_dict)

    # Then: the IPv6Address instance should be created successfully
    assert ipv6_address.value == input_data_dict.get("value")
    assert ipv6_address.author == input_data_dict.get("author")
    assert ipv6_address.markings == input_data_dict.get("markings", [])
    assert ipv6_address.to_stix2_object() is not None


# Invalid Input Tests for IPv6Address
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
        pytest.param(
            {
                "value": "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="invalid_ip_format",
        ),
    ],
)
def test_ipv6address_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the IPv6Address class
    input_data_dict = dict(input_data)

    # When: we try to create a IPv6Address instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        IPv6Address(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for MACAddress
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "00:1B:44:11:3A:B7",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_mac_address_class_should_accept_valid_input(input_data):
    # Given: valid input data for the MACAddress class
    input_data_dict = dict(input_data)
    # When: we create a MACAddress instance
    mac_address = MACAddress(**input_data_dict)

    # Then: the MACAddress instance should be created successfully
    assert mac_address.value == input_data_dict.get("value")
    assert mac_address.author == input_data_dict.get("author")
    assert mac_address.markings == input_data_dict.get("markings", [])
    assert mac_address.to_stix2_object() is not None


# Invalid Input Tests for MACAddress
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
        pytest.param(
            {
                "value": "XX:XX:XX:XX:XX:XX",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="invalid_mac_format",
        ),
    ],
)
def test_mac_address_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the MACAddress class
    input_data_dict = dict(input_data)

    # When: we try to create a MACAddress instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        MACAddress(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for URL
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "https://example.com",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_url_class_should_accept_valid_input(input_data):
    # Given: valid input data for the URL class
    input_data_dict = dict(input_data)
    # When: we create a URL instance
    url = URL(**input_data_dict)

    # Then: the URL instance should be created successfully
    assert url.value == input_data_dict.get("value")
    assert url.author == input_data_dict.get("author")
    assert url.markings == input_data_dict.get("markings", [])
    assert url.to_stix2_object() is not None


# Invalid Input Tests for URL
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
    ],
)
def test_url_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the URL class
    input_data_dict = dict(input_data)

    # When: we try to create a URL instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        URL(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for UserAccount
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "account_login": "user_login",
                "account_type": "type",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "account_login": "user_login",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_user_account_class_should_accept_valid_input(input_data):
    # Given: valid input data for the UserAccount class
    input_data_dict = dict(input_data)
    # When: we create a UserAccount instance
    user_account = UserAccount(**input_data_dict)

    # Then: the UserAccount instance should be created successfully
    assert user_account.account_login == input_data_dict.get("account_login")
    assert user_account.account_type == input_data_dict.get("account_type")
    assert user_account.author == input_data_dict.get("author")
    assert user_account.markings == input_data_dict.get("markings", [])
    assert user_account.to_stix2_object() is not None


# Invalid Input Tests for UserAccount
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "account_login",
            id="missing_account_login_field",
        ),
        pytest.param(
            {
                "account_login": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "account_login",
            id="empty_account_login_field",
        ),
    ],
)
def test_user_account_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the UserAccount class
    input_data_dict = dict(input_data)

    # When: we try to create a UserAccount instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        UserAccount(**input_data_dict)
    assert str(error_field) in str(err)


# Valid Input Tests for UserAgent
@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "value": "Mozilla/5.0",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_user_agent_class_should_accept_valid_input(input_data):
    # Given: valid input data for the UserAgent class
    input_data_dict = dict(input_data)
    # When: we create a UserAgent instance
    user_agent = UserAgent(**input_data_dict)

    # Then: the UserAgent instance should be created successfully
    assert user_agent.value == input_data_dict.get("value")
    assert user_agent.author == input_data_dict.get("author")
    assert user_agent.markings == input_data_dict.get("markings", [])
    assert user_agent.to_stix2_object() is not None


# Invalid Input Tests for UserAgent
@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="missing_value_field",
        ),
        pytest.param(
            {
                "value": "",
                "author": mock_valid_author(),
                "markings": mock_valid_markings(),
            },
            "value",
            id="empty_value_field",
        ),
    ],
)
def test_user_agent_class_should_not_accept_invalid_input(input_data, error_field):
    # Given: valid input data for the UserAgent class
    input_data_dict = dict(input_data)

    # When: we try to create a UserAgent instance
    # Then: a ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        UserAgent(**input_data_dict)
    assert str(error_field) in str(err)
