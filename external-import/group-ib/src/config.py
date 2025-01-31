import os
from pathlib import Path
from typing import Any

import yaml
from cyberintegrations.utils import FileHandler
from pycti import get_config_variable
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.v21.vocab import MALWARE_TYPE


class ConfigConnector:
    collection_map = {
        "apt_threat": "apt/threat",
        "apt_threat_actor": "apt/threat_actor",
        "attacks_ddos": "attacks/ddos",
        "attacks_deface": "attacks/deface",
        "attacks_phishing_group": "attacks/phishing_group",
        "attacks_phishing_kit": "attacks/phishing_kit",
        "compromised_access": "compromised/access",
        "compromised_account_group": "compromised/account_group",
        "compromised_bank_card_group": "compromised/bank_card_group",
        "compromised_discord": "compromised/discord",
        "compromised_imei": "compromised/imei",
        "compromised_masked_card": "compromised/masked_card",
        "compromised_messenger": "compromised/messenger",
        "compromised_mule": "compromised/mule",
        "hi_open_threats": "hi/open_threats",
        "hi_threat": "hi/threat",
        "hi_threat_actor": "hi/threat_actor",
        "ioc_common": "ioc/common",
        "malware_cnc": "malware/cnc",
        "malware_config": "malware/config",
        "malware_malware": "malware/malware",
        "malware_signature": "malware/signature",
        "malware_yara": "malware/yara",
        "osi_git_repository": "osi/git_repository",
        "osi_public_leak": "osi/public_leak",
        "osi_vulnerability": "osi/vulnerability",
        "suspicious_ip_open_proxy": "suspicious_ip/open_proxy",
        "suspicious_ip_scanner": "suspicious_ip/scanner",
        "suspicious_ip_socks_proxy": "suspicious_ip/socks_proxy",
        "suspicious_ip_tor_node": "suspicious_ip/tor_node",
        "suspicious_ip_vpn": "suspicious_ip/vpn",
    }

    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        # Load configuration file
        self.load = self._load_config()
        self.setting_varibles_names_for_env = self._get_setting_varibles_names_for_env(
            data=self.load
        )
        self.setting_varibles_names_for_yml = self._get_setting_varibles_names_for_yml(
            data=self.setting_varibles_names_for_env
        )
        self._initialize_configurations()
        self.collection_mapping_config = FileHandler().read_json_config(
            self.CONFIG_JSON
        )

    def _load_config(self) -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """

        config_file_path = (
            Path(__file__).parents[1].joinpath("src").joinpath("config.yml")
        )
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        return config

    def _get_setting_varibles_names_for_env(
        self, data: dict[str, int | str, bool | dict] | Any
    ) -> list[str]:
        keys = []
        if isinstance(data, dict):
            for key, value in data.items():

                formated_key = key.upper().replace("/", "_")
                if isinstance(value, dict):
                    list_formated_keys = self._get_setting_varibles_names_for_env(
                        data=value
                    )
                    for item_formatted_keys in list_formated_keys:
                        if formated_key in ("OPENCTI", "CONNECTOR"):
                            keys.append(f"{formated_key}_{item_formatted_keys}")
                        else:
                            keys.append(f"{formated_key}__{item_formatted_keys}")
                else:
                    keys.append(formated_key)
        return keys

    def _get_setting_varibles_names_for_yml(self, data: list[str]) -> dict:
        keys = {}
        for env_key in data:
            if "OPENCTI" in env_key or "CONNECTOR" in env_key:
                formated_keys = env_key.lower().split("_")
            else:
                formated_keys = env_key.lower().split("__")
            if len(formated_keys) > 2 and formated_keys[2] == "collections":
                formated_keys[3] = self.collection_map.get(formated_keys[3])
            keys.update({env_key: formated_keys})
        return keys

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """

        for setting_variable in self.setting_varibles_names_for_env:
            attr_name = setting_variable.lower().replace("__", "_")
            attr_value = get_config_variable(
                env_var=setting_variable,
                yaml_path=setting_variable.split("__"),
                config=self.load,
            )
            setattr(self, attr_name, attr_value)

    def get_collection_settings(self, collection, setting_name) -> Any:
        collection_attr_name = f"ti_api_collections_{collection}_{setting_name}"
        return getattr(self, collection_attr_name)

    def get_extra_settings_by_name(self, setting_name):
        cextra_setting_attr_name = f"ti_api_extra_settings_{setting_name}"
        return getattr(self, cextra_setting_attr_name)

    # Set up product metadata
    PRODUCT_TYPE = "SCRIPT"
    PRODUCT_NAME = "OpenCTI"
    PRODUCT_VERSION = "unknown"
    INTEGRATION = "GroupIB_TI_OpenCTI_Connector"
    INTEGRATION_VERSION = "1.0.0"

    # Author
    AUTHOR = "Group-IB"

    # Set project root dir
    ROOT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    # Set basedirs
    DOCS_DIR = os.path.join(ROOT_DIR, "docs")
    LOGS_DIR = os.path.join(ROOT_DIR, "log")

    # Set up logging
    ROOT_LOGGING_LEVEL = "DEBUG"
    LOGGING_FORMAT = (
        "%(asctime)s [%(name)s: %(filename)s.%(lineno)s] [%(levelname)s] %(message)s"
    )

    # Set up logs files
    LOGS_SESSION_FILENAME = "session_ti.log"
    LOGS_INFO_FILENAME = "info_ti.log"
    LOGS_WARNING_FILENAME = "warning_ti.log"

    # Set up config filename
    _config_name_json = "mapping.json"

    # Set up configs
    CONFIG_JSON = os.path.join(DOCS_DIR, "configs", _config_name_json)

    # Set up MITRE Matrix
    MITRE_CACHE_FILENAME = "mitre_cache.json"
    MITRE_CACHE_FOLDER = os.path.join(DOCS_DIR, "cache")

    # Set common mapping variables
    STIX_TLP_MAP = {
        "white": TLP_WHITE,
        "green": TLP_GREEN,
        "amber": TLP_AMBER,
        "red": TLP_RED,
    }
    STIX_MAIN_OBSERVABLE_TYPE_MAP = {
        "domain": "Domain-Name",
        "file": "StixFile",
        "ipv4": "IPv4-Addr",
        "ipv6": "IPv6-Addr",
        "url": "Url",
        "yara": "Unknown",
        "suricata": "Unknown",
    }
    STIX_MALWARE_TYPE_MAP = {*MALWARE_TYPE}
    # ISO3166-1 https://www.iso.org/standard/72482.html
    COUNTRIES = {
        "AF": "Afghanistan",
        "AX": "Åland Islands",
        "AL": "Albania",
        "DZ": "Algeria",
        "AS": "American Samoa",
        "AD": "Andorra",
        "AO": "Angola",
        "AI": "Anguilla",
        "AQ": "Antarctica",
        "AG": "Antigua And Barbuda",
        "AR": "Argentina",
        "AM": "Armenia",
        "AW": "Aruba",
        "AU": "Australia",
        "AT": "Austria",
        "AZ": "Azerbaijan",
        "BS": "Bahamas",
        "BH": "Bahrain",
        "BD": "Bangladesh",
        "BB": "Barbados",
        "BY": "Belarus",
        "BE": "Belgium",
        "BZ": "Belize",
        "BJ": "Benin",
        "BM": "Bermuda",
        "BT": "Bhutan",
        "BO": "Bolivia",
        ## "BQ": "Bonaire, Sint Eustatius and Saba",
        "BA": "Bosnia and Herzegovina",
        "BW": "Botswana",
        "BV": "Bouvet Island",
        "BR": "Brazil",
        "IO": "British Indian Ocean Territory",
        "BN": "Brunei Darussalam",
        "BG": "Bulgaria",
        "BF": "Burkina Faso",
        "BI": "Burundi",
        "KH": "Cambodia",
        "CM": "Cameroon",
        "CA": "Canada",
        "CV": "Cape Verde",
        "KY": "Cayman Islands",
        "CF": "Central African Republic",
        "TD": "Chad",
        "CL": "Chile",
        "CN": "China",
        "CX": "Christmas Island",
        "CC": "Cocos (Keeling) Islands",
        "CO": "Colombia",
        "KM": "Comoros",
        "CG": "Congo",
        "CD": "Congo, The Democratic Republic Of The",
        "CK": "Cook Islands",
        "CR": "Costa Rica",
        "CI": "Cote D'ivoire",
        "HR": "Croatia",
        "CU": "Cuba",
        "CW": "Country of Curaçao",
        "CY": "Cyprus",
        "CZ": "Czech Republic",
        "DK": "Denmark",
        "DJ": "Djibouti",
        "DM": "Dominica",
        "DO": "Dominican Republic",
        "EC": "Ecuador",
        "EG": "Egypt",
        "SV": "El Salvador",
        "GQ": "Equatorial Guinea",
        "ER": "Eritrea",
        "EE": "Estonia",
        "ET": "Ethiopia",
        "FK": "Falkland Islands (Malvinas)",
        "FO": "Faroe Islands",
        "FJ": "Fiji",
        "FI": "Finland",
        "FR": "France",
        "GF": "French Guiana",
        "PF": "French Polynesia",
        "TF": "French Southern Territories",
        "GA": "Gabon",
        "GM": "Gambia",
        "GE": "Georgia",
        "DE": "Germany",
        "GH": "Ghana",
        "GI": "Gibraltar",
        "GR": "Greece",
        "GL": "Greenland",
        "GD": "Grenada",
        "GP": "Guadeloupe",
        "GU": "Guam",
        "GT": "Guatemala",
        "GG": "Guernsey",
        "GN": "Guinea",
        "GW": "Guinea-bissau",
        "GY": "Guyana",
        "HT": "Haiti",
        "HM": "Heard Island And Mcdonald Islands",
        "VA": "Holy See (Vatican City State)",
        "HN": "Honduras",
        "HK": "Hong Kong",
        "HU": "Hungary",
        "IS": "Iceland",
        "IN": "India",
        "ID": "Indonesia",
        "IR": "Iran, Islamic Republic Of",
        "IQ": "Iraq",
        "IE": "Ireland",
        "IM": "Isle Of Man",
        "IL": "Israel",
        "IT": "Italy",
        "JM": "Jamaica",
        "JP": "Japan",
        "JE": "Jersey",
        "JO": "Jordan",
        "KZ": "Kazakhstan",
        "KE": "Kenya",
        "KI": "Kiribati",
        "KP": "Korea, Democratic People's Republic Of",
        "KR": "Korea, Republic Of",
        "KW": "Kuwait",
        "KG": "Kyrgyzstan",
        "LA": "Lao People's Democratic Republic",
        "LV": "Latvia",
        "LB": "Lebanon",
        "LS": "Lesotho",
        "LR": "Liberia",
        "LY": "Libyan Arab Jamahiriya",
        "LI": "Liechtenstein",
        "LT": "Lithuania",
        "LU": "Luxembourg",
        "MO": "Macao",
        "MK": "Macedonia, The Former Yugoslav Republic Of",
        "MG": "Madagascar",
        "MW": "Malawi",
        "MY": "Malaysia",
        "MV": "Maldives",
        "ML": "Mali",
        "MT": "Malta",
        "MH": "Marshall Islands",
        "MQ": "Martinique",
        "MR": "Mauritania",
        "MU": "Mauritius",
        "YT": "Mayotte",
        "MX": "Mexico",
        "FM": "Micronesia, Federated States Of",
        "MD": "Moldova, Republic Of",
        "MC": "Monaco",
        "MN": "Mongolia",
        "ME": "Montenegro",
        "MS": "Montserrat",
        "MA": "Morocco",
        "MZ": "Mozambique",
        "MM": "Myanmar",
        "NA": "Namibia",
        "NR": "Nauru",
        "NP": "Nepal",
        "NL": "Netherlands",
        "NC": "New Caledonia",
        "NZ": "New Zealand",
        "NI": "Nicaragua",
        "NE": "Niger",
        "NG": "Nigeria",
        "NU": "Niue",
        "NF": "Norfolk Island",
        "MP": "Northern Mariana Islands",
        "NO": "Norway",
        "OM": "Oman",
        "PK": "Pakistan",
        "PW": "Palau",
        "PS": "Palestinian Territory, Occupied",
        "PA": "Panama",
        "PG": "Papua New Guinea",
        "PY": "Paraguay",
        "PE": "Peru",
        "PH": "Philippines",
        "PN": "Pitcairn",
        "PL": "Poland",
        "PT": "Portugal",
        "PR": "Puerto Rico",
        "QA": "Qatar",
        "RE": "Reunion",
        "RO": "Romania",
        "RU": "Russian Federation",
        "RW": "Rwanda",
        ## "BL": "Saint Barthelemy",
        "SH": "Saint Helena",
        "KN": "Saint Kitts And Nevis",
        "LC": "Saint Lucia",
        ## "MF": "Saint Martin (French part)",
        "PM": "Saint Pierre And Miquelon",
        "VC": "Saint Vincent And The Grenadines",
        "WS": "Samoa",
        "SM": "San Marino",
        "ST": "Sao Tome And Principe",
        "SA": "Saudi Arabia",
        "SN": "Senegal",
        "RS": "Serbia",
        "SC": "Seychelles",
        "SL": "Sierra Leone",
        "SG": "Singapore",
        ## "SX": "Sint Maarten (Dutch part)",
        "SK": "Slovakia",
        "SI": "Slovenia",
        "SB": "Solomon Islands",
        "SO": "Somalia",
        "ZA": "South Africa",
        "GS": "South Georgia And The South Sandwich Islands",
        ## "SS": "South Sudan",
        "ES": "Spain",
        "LK": "Sri Lanka",
        "SD": "Sudan",
        "SR": "Suriname",
        "SJ": "Svalbard And Jan Mayen",
        "SZ": "Swaziland",
        "SE": "Sweden",
        "CH": "Switzerland",
        "SY": "Syrian Arab Republic",
        "TW": "Taiwan, Province Of China",
        "TJ": "Tajikistan",
        "TZ": "Tanzania, United Republic Of",
        "TH": "Thailand",
        "TL": "Timor-leste",
        "TG": "Togo",
        "TK": "Tokelau",
        "TO": "Tonga",
        "TT": "Trinidad And Tobago",
        "TN": "Tunisia",
        "TR": "Turkey",
        "TM": "Turkmenistan",
        "TC": "Turks And Caicos Islands",
        "TV": "Tuvalu",
        "UG": "Uganda",
        "UA": "Ukraine",
        "AE": "United Arab Emirates",
        "GB": "United Kingdom",
        "US": "United States",
        "UM": "United States Minor Outlying Islands",
        "UY": "Uruguay",
        "UZ": "Uzbekistan",
        "VU": "Vanuatu",
        "VE": "Venezuela",
        "VN": "Viet Nam",
        "VG": "Virgin Islands, British",
        "VI": "Virgin Islands, U.S.",
        "WF": "Wallis And Futuna",
        "EH": "Western Sahara",
        "YE": "Yemen",
        "ZM": "Zambia",
        "ZW": "Zimbabwe",
    }
    STIX_COUNTRY_TYPE_MAP = {
        "country": "Country",
        "city": "City",
        "state": "Administrative-Area",
    }
    STIX_REPORT_TYPE_MAP = {"threat_report": "Threat-Report"}
    STIX_RELATION_TYPE_MAP = {
        "indicator": "based-on",
        "attack_pattern": "indicates",
        "malware": "indicates",
        "threat_actor": "indicates",
    }
