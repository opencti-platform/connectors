import json
import os
import re
import sys
import time
from datetime import datetime

import stix2
import yaml
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    CustomObservablePhoneNumber,
    CustomObservableText,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    StixSightingRelationship,
    Tool,
    get_config_variable,
)

PATTERNTYPES = ["yara", "sigma", "pcre", "snort", "suricata"]
OPENCTISTIX2 = {
    "autonomous-system": {
        "type": "autonomous-system",
        "path": ["number"],
        "transform": {"operation": "remove_string", "value": "AS"},
    },
    "mac-addr": {"type": "mac-addr", "path": ["value"]},
    "hostname": {"type": "hostname", "path": ["value"]},
    "domain": {"type": "domain-name", "path": ["value"]},
    "ipv4-addr": {"type": "ipv4-addr", "path": ["value"]},
    "ipv6-addr": {"type": "ipv6-addr", "path": ["value"]},
    "url": {"type": "url", "path": ["value"]},
    "link": {"type": "url", "path": ["value"]},
    "email-address": {"type": "email-addr", "path": ["value"]},
    "email-subject": {"type": "email-message", "path": ["subject"]},
    "mutex": {"type": "mutex", "path": ["name"]},
    "file-name": {"type": "file", "path": ["name"]},
    "file-path": {"type": "file", "path": ["name"]},
    "file-md5": {"type": "file", "path": ["hashes", "MD5"]},
    "file-sha1": {"type": "file", "path": ["hashes", "SHA-1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA-256"]},
    "directory": {"type": "directory", "path": ["path"]},
    "registry-key": {"type": "windows-registry-key", "path": ["key"]},
    "registry-key-value": {"type": "windows-registry-value-type", "path": ["data"]},
    "pdb-path": {"type": "file", "path": ["name"]},
    "x509-certificate-issuer": {"type": "x509-certificate", "path": ["issuer"]},
    "x509-certificate-serial-number": {
        "type": "x509-certificate",
        "path": ["serial_number"],
    },
    "text": {"type": "text", "path": ["value"]},
    "user-agent": {"type": "user-agent", "path": ["value"]},
    "phone-number": {"type": "phone-number", "path": ["value"]},
    "user-account": {"type": "user-account", "path": ["account_login"]},
    "user-account-github": {
        "type": "user-account",
        "path": ["account_login"],
        "account_type": "github",
    },
    "identity-individual": {"type": "identity", "identity_class": "individual"},
}
FILETYPES = ["file-name", "file-md5", "file-sha1", "file-sha256"]


class MispImportFile:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.misp_import_file_import_from_date = get_config_variable(
            "MISP_IMPORT_FILE_IMPORT_FROM_DATE",
            ["misp_import_file", "import_from_date"],
            config,
        )
        self.misp_import_file_create_reports = get_config_variable(
            "MISP_IMPORT_FILE_CREATE_REPORTS",
            ["misp_import_file", "create_reports"],
            config,
            False,
            True,
        )
        self.misp_import_file_report_type = get_config_variable(
            "MISP_IMPORT_FILE_REPORT_TYPE",
            ["misp_import_file", "report_type"],
            config,
            False,
            "misp-event",
        )
        self.misp_import_file_create_indicators = get_config_variable(
            "MISP_IMPORT_FILE_CREATE_INDICATORS",
            ["misp_import_file", "create_indicators"],
            config,
        )
        self.misp_import_file_create_observables = get_config_variable(
            "MISP_IMPORT_FILE_CREATE_OBSERVABLES",
            ["misp_import_file", "create_observables"],
            config,
        )
        self.misp_import_file_create_tags_as_labels = get_config_variable(
            "MISP_CREATE_TAGS_AS_LABELS",
            ["misp_import_file", "create_tags_as_labels"],
            config,
            default=True,
        )
        self.misp_import_file_guess_threats_from_tags = get_config_variable(
            "MISP_IMPORT_FILE_GUESS_THREAT_FROM_TAGS",
            ["misp_import_file", "guess_threats_from_tags"],
            config,
            default=False,
        )
        self.misp_import_file_author_from_tags = get_config_variable(
            "MISP_IMPORT_FILE_AUTHOR_FROM_TAGS",
            ["misp_import_file", "author_from_tags"],
            config,
            default=False,
        )
        self.misp_import_file_markings_from_tags = get_config_variable(
            "MISP_IMPORT_FILE_MARKINGS_FROM_TAGS",
            ["misp_import_file", "markings_from_tags"],
            config,
            default=False,
        )
        self.misp_import_file_create_object_observables = get_config_variable(
            "MISP_IMPORT_FILE_CREATE_OBJECT_OBSERVABLES",
            ["misp_import_file", "create_object_observables"],
            config,
            False,
            False,
        )
        self.misp_import_file_import_to_ids_no_score = get_config_variable(
            "MISP_IMPORT_FILE_IMPORT_TO_IDS_NO_SCORE",
            ["misp_import_file", "import_to_ids_no_score"],
            config,
            True,
        )
        self.misp_import_file_import_with_attachments = bool(
            get_config_variable(
                "MISP_IMPORT_FILE_IMPORT_WITH_ATTACHMENTS",
                ["misp_import_file", "import_with_attachments"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.misp_import_file_import_unsupported_observables_as_text = bool(
            get_config_variable(
                "MISP_IMPORT_FILE_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT",
                ["misp_import_file", "import_unsupported_observables_as_text"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.misp_import_file_import_unsupported_observables_as_text_transparent = bool(
            get_config_variable(
                "MISP_IMPORT_FILE_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT",
                [
                    "misp_import_file",
                    "import_unsupported_observables_as_text_transparent",
                ],
                config,
                isNumber=False,
                default=True,
            )
        )

    def _resolve_markings(self, tags, with_default=True):
        markings = []
        for tag in tags:
            tag_name = tag["name"]
            tag_name_lower = tag["name"].lower()
            if self.misp_import_file_markings_from_tags:
                if (
                    ":" in tag_name
                    and "=" in tag_name
                    and tag_name_lower.startswith("marking")
                ):
                    marking_definition_split = tag_name.split(":")
                    # Check if second part also contains ":"
                    if len(marking_definition_split) > 2:
                        # Example: marking:PAP=PAP:RED
                        # "PAP=PAP" + "RED"
                        marking_definition = (
                            marking_definition_split[1]
                            + ":"
                            + marking_definition_split[2]
                        )
                    else:
                        # Example: marking:CLASSIFICATION=DIFFUSION RESTREINTE
                        # CLASSIFICATION=DIFFUSION RESTREINTE
                        marking_definition = marking_definition_split[1]

                    # Split on the equal
                    marking_definition_split2 = marking_definition.split("=")

                    # PAP
                    # CLASSIFICATION
                    marking_type = marking_definition_split2[0]

                    # PAP:RED
                    # DIFFUSION RESTREINTE
                    marking_name = marking_definition_split2[1]

                    marking = stix2.MarkingDefinition(
                        id=MarkingDefinition.generate_id(marking_type, marking_name),
                        definition_type="statement",
                        definition={"statement": "custom"},
                        allow_custom=True,
                        x_opencti_definition_type=marking_type,
                        x_opencti_definition=marking_name,
                    )
                    markings.append(marking)
            if tag_name_lower == "tlp:clear":
                markings.append(stix2.TLP_WHITE)
            if tag_name_lower == "tlp:white":
                markings.append(stix2.TLP_WHITE)
            if tag_name_lower == "tlp:green":
                markings.append(stix2.TLP_GREEN)
            if tag_name_lower == "tlp:amber":
                markings.append(stix2.TLP_AMBER)
            if tag_name_lower == "tlp:amber+strict":
                marking = stix2.MarkingDefinition(
                    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "custom"},
                    allow_custom=True,
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                )
                markings.append(marking)
            if tag_name_lower == "tlp:red":
                markings.append(stix2.TLP_RED)
        if len(markings) == 0 and with_default:
            markings.append(stix2.TLP_WHITE)
        return markings

    def _prepare_elements(self, galaxies, tags, author, markings):
        elements = {
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "sectors": [],
            "countries": [],
        }
        added_names = []
        for galaxy in galaxies:
            if "namespace" not in galaxy:
                self.helper.log_info("Skipping galaxy without namespace")
                continue
            # Get the linked intrusion sets
            if (
                (
                    galaxy["namespace"] == "mitre-attack"
                    and galaxy["name"] == "Intrusion Set"
                )
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Threat Actor")
                or (
                    galaxy["namespace"] == "misp"
                    and galaxy["name"] == "Microsoft Activity Group actor"
                )
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - G" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - G")[0]
                    elif "APT " in galaxy_entity["value"]:
                        name = galaxy_entity["value"].replace("APT ", "APT")
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["intrusion_sets"].append(
                            stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                labels=["intrusion-set"],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={"x_opencti_aliases": aliases},
                            )
                        )
                        added_names.append(name)
            # Get the linked tools
            if galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Tool":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["tools"].append(
                            stix2.Tool(
                                id=Tool.generate_id(name),
                                name=name,
                                labels=["tool"],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={"x_opencti_aliases": aliases},
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked malwares
            if (
                (galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Malware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Tool")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Ransomware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Android")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Malpedia")
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["malwares"].append(
                            stix2.Malware(
                                id=Malware.generate_id(name),
                                name=name,
                                is_family=True,
                                aliases=aliases,
                                labels=[galaxy["name"]],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked attack_patterns
            if (
                galaxy["namespace"] == "mitre-attack"
                and galaxy["name"] == "Attack Pattern"
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - T" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - T")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        x_mitre_id = None
                        if "external_id" in galaxy_entity["meta"]:
                            if len(galaxy_entity["meta"]["external_id"]) > 0:
                                x_mitre_id = galaxy_entity["meta"]["external_id"][0]
                        elements["attack_patterns"].append(
                            stix2.AttackPattern(
                                id=AttackPattern.generate_id(name, x_mitre_id),
                                name=name,
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={
                                    "x_mitre_id": x_mitre_id,
                                    "x_opencti_aliases": aliases,
                                },
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked sectors
            if galaxy["namespace"] == "misp" and galaxy["name"] == "Sector":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    name = galaxy_entity["value"]
                    if name not in added_names:
                        elements["sectors"].append(
                            stix2.Identity(
                                id=Identity.generate_id(name, "class"),
                                name=name,
                                identity_class="class",
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked countries
            if galaxy["namespace"] == "misp" and galaxy["name"] == "Country":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    name = galaxy_entity["description"]
                    if name not in added_names:
                        elements["countries"].append(
                            stix2.Location(
                                id=Location.generate_id(name, "Country"),
                                name=name,
                                country=galaxy_entity["meta"]["ISO"],
                                description="Imported from MISP tag",
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
        for tag in tags:
            # Try to guess from tags
            if self.misp_import_file_guess_threats_from_tags:
                tag_value_split = tag["name"].split("=")
                if len(tag_value_split) == 1:
                    tag_value = tag_value_split[0]
                else:
                    tag_value = tag_value_split[1].replace('"', "")
                tag_value_split = tag_value.split(":")
                if len(tag_value_split) == 1:
                    tag_value = tag_value_split[0]
                else:
                    tag_value = tag_value_split[1].replace('"', "")
                threats = self.helper.api.stix_domain_object.list(
                    types=["Intrusion-Set", "Malware", "Tool", "Attack-Pattern"],
                    filters={
                        "mode": "and",
                        "filters": [
                            {
                                "key": [
                                    "name",
                                    "x_mitre_id",
                                    "aliases",
                                    "x_opencti_aliases",
                                ],
                                "values": [tag_value],
                            }
                        ],
                        "filterGroups": [],
                    },
                )
                if len(threats) > 0:
                    threat = threats[0]
                    if threat["name"] not in added_names:
                        if threat["entity_type"] == "Intrusion-Set":
                            elements["intrusion_sets"].append(
                                stix2.IntrusionSet(
                                    id=IntrusionSet.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                            )
                            added_names.append(threat["name"])
                        if threat["entity_type"] == "Malware":
                            elements["malwares"].append(
                                stix2.Malware(
                                    id=Malware.generate_id(threat["name"]),
                                    name=threat["name"],
                                    is_family=True,
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                            )
                            added_names.append(threat["name"])
                        if threat["entity_type"] == "Tool":
                            elements["tools"].append(
                                stix2.Tool(
                                    id=Tool.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                            )
                            added_names.append(threat["name"])
                        if threat["entity_type"] == "Attack-Pattern":
                            elements["attack_patterns"].append(
                                stix2.AttackPattern(
                                    id=AttackPattern.generate_id(threat["name"]),
                                    name=threat["name"],
                                    confidence=self.helper.connect_confidence_level,
                                    created_by_ref=author["id"],
                                    object_marking_refs=markings,
                                    allow_custom=True,
                                )
                            )
                            added_names.append(threat["name"])
            # Get the linked intrusion sets
            if (
                tag["name"].startswith("misp-galaxy:threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                or tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                or tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                or tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
                or tag["name"].startswith("intrusion-set")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - G" in tag_value:
                        name = tag_value.split(" - G")[0]
                    elif "APT " in tag_value:
                        name = tag_value.replace("APT ", "APT")
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["intrusion_sets"].append(
                            stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked tools
            if (
                tag["name"].startswith("misp-galaxy:mitre-tool")
                or tag["name"].startswith("misp-galaxy:mitre-enterprise-attack-tool")
                or tag["name"].startswith("tool")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - S" in tag_value:
                        name = tag_value.split(" - S")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["tools"].append(
                            stix2.Tool(
                                id=Tool.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked malwares
            if (
                tag["name"].startswith("misp-galaxy:mitre-malware")
                or tag["name"].startswith("misp-galaxy:mitre-enterprise-attack-malware")
                or tag["name"].startswith("misp-galaxy:misp-ransomware")
                or tag["name"].startswith("misp-galaxy:misp-tool")
                or tag["name"].startswith("misp-galaxy:misp-android")
                or tag["name"].startswith("misp-galaxy:misp-malpedia")
                or tag["name"].startswith("malware")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - S" in tag_value:
                        name = tag_value.split(" - S")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["malwares"].append(
                            stix2.Malware(
                                id=Malware.generate_id(name),
                                name=name,
                                is_family=True,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked attack_patterns
            if (
                tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                or tag["name"].startswith("misp-galaxy:attack-pattern")
                or tag["name"].startswith("mitre-attack:attack-pattern")
                or tag["name"].startswith("mitre:")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - T" in tag_value:
                        name = tag_value.split(" - T")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["attack_patterns"].append(
                            stix2.AttackPattern(
                                id=AttackPattern.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked sectors
            if tag["name"].startswith("misp-galaxy:sector"):
                tag_value_split = tag["name"].split('="')
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    name = tag_value_split[1][:-1].strip()
                    if name not in added_names:
                        elements["sectors"].append(
                            stix2.Identity(
                                id=Identity.generate_id(name, "class"),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                identity_class="class",
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
        return elements

    def _resolve_tags(self, tags):
        opencti_tags = []

        if not self.misp_import_file_create_tags_as_labels:
            return opencti_tags

        for tag in tags:
            if (
                tag["name"] != "tlp:white"
                and tag["name"] != "tlp:green"
                and tag["name"] != "tlp:amber"
                and tag["name"] != "tlp:amber+strict"
                and tag["name"] != "tlp:red"
                and not tag["name"].startswith("misp-galaxy:threat-actor")
                and not tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                and not tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-malware")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-malware"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-tool")
                and not tag["name"].startswith("misp-galaxy:tool")
                and not tag["name"].startswith("misp-galaxy:ransomware")
                and not tag["name"].startswith("misp-galaxy:malpedia")
                and not tag["name"].startswith("misp-galaxy:sector")
                and not tag["name"].startswith("misp-galaxy:country")
                and not tag["name"].startswith("marking")
                and not tag["name"].startswith("creator")
                and not tag["name"].startswith("intrusion-set")
                and not tag["name"].startswith("malware")
                and not tag["name"].startswith("tool")
                and not tag["name"].startswith("mitre")
            ):
                tag_value = tag["name"]
                if '="' in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                    if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                        tag_value = tag_value_split[1][:-1].strip()
                elif ":" in tag["name"]:
                    tag_value_split = tag["name"].split(":")
                    if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                        tag_value = tag_value_split[1].strip()
                if tag_value.isdigit():
                    if ":" in tag["name"]:
                        tag_value_split = tag["name"].split(":")
                        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                            tag_value = tag_value_split[1].strip()
                    else:
                        tag_value = tag["name"]
                if '="' in tag_value:
                    if len(tag_value) > 0:
                        tag_value = tag_value.replace('="', "-")[:-1]
                opencti_tags.append(tag_value)
        return opencti_tags

    def _resolve_type(self, type, value):
        types = {
            "yara": [{"resolver": "yara"}],
            "sigma": [{"resolver": "sigma"}],
            "md5": [{"resolver": "file-md5", "type": "File"}],
            "sha1": [{"resolver": "file-sha1", "type": "File"}],
            "sha256": [{"resolver": "file-sha256", "type": "File"}],
            "filename": [{"resolver": "file-name", "type": "File"}],
            "pdb": [{"resolver": "pdb-path", "type": "File"}],
            "filename|md5": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-md5", "type": "File"},
            ],
            "filename|sha1": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha1", "type": "File"},
            ],
            "filename|sha256": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha256", "type": "File"},
            ],
            "ip-src": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "ip-dst": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "ip-src|port": [
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
                {"resolver": "text", "type": "Text"},
            ],
            "ip-dst|port": [
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
                {"resolver": "text", "type": "Text"},
            ],
            "hostname": [{"resolver": "hostname", "type": "Hostname"}],
            "hostname|port": [
                {"resolver": "hostname", "type": "Hostname"},
                {"resolver": "text", "type": "Text"},
            ],
            "domain": [{"resolver": "domain", "type": "Domain-Name"}],
            "domain|ip": [
                {"resolver": "domain", "type": "Domain-Name"},
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
            ],
            "email-subject": [{"resolver": "email-subject", "type": "Email-Message"}],
            "email": [{"resolver": "email-address", "type": "Email-Addr"}],
            "email-src": [{"resolver": "email-address", "type": "Email-Addr"}],
            "email-dst": [{"resolver": "email-address", "type": "Email-Addr"}],
            "url": [{"resolver": "url", "type": "Url"}],
            "windows-scheduled-task": [
                {"resolver": "windows-scheduled-task", "type": "Text"}
            ],
            "regkey": [{"resolver": "registry-key", "type": "Windows-Registry-Key"}],
            "user-agent": [{"resolver": "user-agent", "type": "User-Agent"}],
            "phone-number": [{"resolver": "phone-number", "type": "Phone-Number"}],
            "whois-registrant-email": [
                {"resolver": "email-address", "type": "Email-Addr"}
            ],
            "text": [{"resolver": "text", "type": "Text"}],
            "github-username": [
                {"resolver": "user-account-github", "type": "User-Account"}
            ],
            "full-name": [{"resolver": "identity-individual", "type": "Identity"}],
        }
        if type in types:
            resolved_types = types[type]
            if len(resolved_types) == 2:
                values = value.split("|")
                if len(values) == 2:
                    if resolved_types[0]["resolver"] == "ipv4-addr":
                        resolver_0 = self._detect_ip_version(values[0])
                        type_0 = self._detect_ip_version(values[0], True)
                    else:
                        resolver_0 = resolved_types[0]["resolver"]
                        type_0 = resolved_types[0]["type"]
                    if resolved_types[1]["resolver"] == "ipv4-addr":
                        resolver_1 = self._detect_ip_version(values[1])
                        type_1 = self._detect_ip_version(values[1], True)
                    else:
                        resolver_1 = resolved_types[1]["resolver"]
                        type_1 = resolved_types[1]["type"]
                    return [
                        {"resolver": resolver_0, "type": type_0, "value": values[0]},
                        {"resolver": resolver_1, "type": type_1, "value": values[1]},
                    ]
                else:
                    return None
            else:
                if (
                    "resolver" in resolved_types[0]
                    and resolved_types[0]["resolver"] == "ipv4-addr"
                    or resolved_types[0] == "ipv4-addr"
                ):
                    resolver_0 = self._detect_ip_version(value)
                    type_0 = self._detect_ip_version(value, True)
                else:
                    resolver_0 = resolved_types[0]["resolver"]
                    type_0 = (
                        resolved_types[0]["type"]
                        if "type" in resolved_types[0]
                        else None
                    )
                return [{"resolver": resolver_0, "type": type_0, "value": value}]
        # If not found, return text observable as a fallback
        if self.misp_import_file_import_unsupported_observables_as_text:
            return [
                {
                    "resolver": "text",
                    "type": "Text",
                    "value": value + " (type=" + type + ")",
                }
            ]
        else:
            return None

    def _detect_ip_version(self, value, type=False):
        if re.match(
            r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/([1-9]|[1-2]\d|3[0-2]))?$",
            value,
        ):
            if type:
                return "IPv4-Addr"
            return "ipv4-addr"
        else:
            if type:
                return "IPv6-Addr"
            return "ipv6-addr"

    def _get_pdf_file(self, attribute):
        if not self.misp_import_file_import_with_attachments:
            return None

        attr_type = attribute["type"]
        attr_category = attribute["category"]
        if not (attr_type == "attachment" and attr_category == "External analysis"):
            return None

        attr_value = attribute["value"]
        if not attr_value.endswith((".pdf", ".PDF")):
            return None

        attr_uuid = attribute["uuid"]

        attr_data = attribute.get("data")
        if attr_data is None:
            self.helper.log_error(
                "No data for attribute: {0} ({1}:{2})".format(
                    attr_uuid, attr_type, attr_category
                )
            )
            return None

        self.helper.log_info(
            "Found PDF '{0}' for attribute: {1} ({2}:{3})".format(
                attr_value, attr_uuid, attr_type, attr_category
            )
        )

        return {
            "name": attr_value,
            "data": attr_data,
            "mime_type": "application/pdf",
            "no_trigger_import": True,
        }

    def _threat_level_to_score(self, threat_level):
        if threat_level == "1":
            score = 90
        elif threat_level == "2":
            score = 60
        elif threat_level == "3":
            score = 30
        else:
            score = 50
        return score

    def _process_attribute(
        self,
        author: stix2.Identity,
        event_elements,
        event_markings,
        event_labels,
        object_observable,
        attribute_external_references,
        attribute,
        event_threat_level,
        create_relationships,
    ):
        if attribute["type"] == "link" and attribute["category"] == "External analysis":
            return None
        resolved_attributes = self._resolve_type(attribute["type"], attribute["value"])
        if resolved_attributes is None:
            return None

        file_name = None
        for resolved_attribute in resolved_attributes:
            if resolved_attribute["resolver"] == "file-name":
                file_name = resolved_attribute["value"]

        for resolved_attribute in resolved_attributes:
            ### Pre-process
            # Markings & Tags
            attribute_tags = event_labels
            if "Tag" in attribute:
                attribute_markings = self._resolve_markings(
                    attribute["Tag"], with_default=False
                )
                attribute_tags = self._resolve_tags(attribute["Tag"])
                if len(attribute_markings) == 0:
                    attribute_markings = event_markings
            else:
                attribute_markings = event_markings

            # Elements
            attribute_elements = self._prepare_elements(
                attribute.get("Galaxy", []),
                attribute.get("Tag", []),
                author,
                attribute_markings,
            )

            ### Create the indicator
            observable_resolver = resolved_attribute["resolver"]
            observable_type = resolved_attribute["type"]
            observable_value = resolved_attribute["value"]
            name = (
                resolved_attribute["value"]
                if len(resolved_attribute["value"]) > 2
                else (
                    attribute["comment"]
                    if len(attribute["comment"]) > 2
                    else observable_type
                )
            )
            pattern_type = "stix"
            pattern = None
            # observable type is yara or sigma for instance
            if observable_resolver in PATTERNTYPES:
                pattern_type = observable_resolver
                pattern = observable_value
                name = (
                    attribute["comment"]
                    if len(attribute["comment"]) > 2
                    else observable_type
                )
            # observable type is not in stix 2
            elif observable_resolver not in OPENCTISTIX2:
                return None
            # observable type is in stix
            elif "path" in OPENCTISTIX2[observable_resolver]:
                if "transform" in OPENCTISTIX2[observable_resolver]:
                    if (
                        OPENCTISTIX2[observable_resolver]["transform"]["operation"]
                        == "remove_string"
                    ):
                        observable_value = observable_value.replace(
                            OPENCTISTIX2[observable_resolver]["transform"]["value"],
                            "",
                        )
                lhs = stix2.ObjectPath(
                    OPENCTISTIX2[observable_resolver]["type"],
                    OPENCTISTIX2[observable_resolver]["path"],
                )
                genuine_pattern = str(
                    stix2.ObservationExpression(
                        stix2.EqualityComparisonExpression(lhs, observable_value)
                    )
                )
                pattern = genuine_pattern

            to_ids = attribute["to_ids"]
            score = self._threat_level_to_score(event_threat_level)
            if self.misp_import_file_import_to_ids_no_score is not None and not to_ids:
                score = self.misp_import_file_import_to_ids_no_score

            indicator = None
            if self.misp_import_file_create_indicators and pattern is not None:
                try:
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=name,
                        description=attribute["comment"],
                        confidence=self.helper.connect_confidence_level,
                        pattern_type=pattern_type,
                        pattern=pattern,
                        valid_from=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        labels=attribute_tags,
                        created_by_ref=author["id"],
                        object_marking_refs=attribute_markings,
                        external_references=attribute_external_references,
                        created=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        modified=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        custom_properties={
                            "x_opencti_main_observable_type": observable_type,
                            "x_opencti_detection": to_ids,
                            "x_opencti_score": score,
                        },
                    )
                except Exception as e:
                    self.helper.log_error(f"Error processing indicator {name}: {e}")
            observable = None
            if self.misp_import_file_create_observables and observable_type is not None:
                try:
                    custom_properties = {
                        "x_opencti_description": attribute["comment"],
                        "x_opencti_score": score,
                        "labels": attribute_tags,
                        "created_by_ref": author["id"],
                        "external_references": attribute_external_references,
                    }
                    observable = None
                    if observable_type == "Autonomous-System":
                        observable = stix2.AutonomousSystem(
                            number=observable_value.replace("AS", ""),
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mac-Addr":
                        observable = stix2.MACAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Hostname":
                        observable = CustomObservableHostname(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Domain-Name":
                        observable = stix2.DomainName(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv4-Addr":
                        observable = stix2.IPv4Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv6-Addr":
                        observable = stix2.IPv6Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Url":
                        observable = stix2.URL(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Addr":
                        observable = stix2.EmailAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Message":
                        observable = stix2.EmailMessage(
                            subject=observable_value,
                            is_multipart=True,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mutex":
                        observable = stix2.Mutex(
                            name=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "User-Account":
                        if "account_type" in OPENCTISTIX2[observable_resolver]:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                account_type=OPENCTISTIX2[observable_resolver][
                                    "account_type"
                                ],
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        else:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "File":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "name":
                            observable = stix2.File(
                                name=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif OPENCTISTIX2[observable_resolver]["path"][0] == "hashes":
                            hashes = {}
                            hashes[OPENCTISTIX2[observable_resolver]["path"][1]] = (
                                observable_value
                            )
                            observable = stix2.File(
                                name=file_name,
                                hashes=hashes,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Directory":
                        observable = stix2.Directory(
                            path=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Key":
                        observable = stix2.WindowsRegistryKey(
                            key=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Value-Type":
                        observable = stix2.WindowsRegistryValueType(
                            data=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "X509-Certificate":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "issuer":
                            observable = stix2.File(
                                issuer=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif (
                            OPENCTISTIX2[observable_resolver]["path"][1]
                            == "serial_number"
                        ):
                            observable = stix2.File(
                                serial_number=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Phone-Number":
                        observable = CustomObservablePhoneNumber(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Text":
                        observable = CustomObservableText(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Identity":
                        observable = stix2.Identity(
                            id=Identity.generate_id(
                                observable_value,
                                OPENCTISTIX2[observable_resolver]["identity_class"],
                            ),
                            name=observable_value,
                            identity_class=OPENCTISTIX2[observable_resolver][
                                "identity_class"
                            ],
                            description=attribute["comment"],
                            labels=attribute_tags,
                            created_by_ref=author["id"],
                            external_references=attribute_external_references,
                        )
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating observable type {observable_type} with value {observable_value}: {e}"
                    )
            sightings = []
            identities = []
            if "Sighting" in attribute:
                for misp_sighting in attribute["Sighting"]:
                    if (
                        "Organisation" in misp_sighting
                        and misp_sighting["Organisation"]["name"] != author.name
                    ):
                        sighted_by = stix2.Identity(
                            id=Identity.generate_id(
                                misp_sighting["Organisation"]["name"], "organization"
                            ),
                            name=misp_sighting["Organisation"]["name"],
                            identity_class="organization",
                        )
                        identities.append(sighted_by)
                    else:
                        sighted_by = None

                    if indicator is not None and sighted_by is not None:
                        sighting = stix2.Sighting(
                            id=StixSightingRelationship.generate_id(
                                indicator["id"],
                                sighted_by["id"],
                                datetime.utcfromtimestamp(
                                    int(misp_sighting["date_sighting"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                datetime.utcfromtimestamp(
                                    int(misp_sighting["date_sighting"]) + 3600
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            ),
                            sighting_of_ref=indicator["id"],
                            first_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            last_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"]) + 3600
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            where_sighted_refs=[sighted_by],
                        )
                        sightings.append(sighting)
                    # if observable is not None:
                    #     sighting = Sighting(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id("sighting"),
                    #         sighting_of_ref=observable["id"],
                    #         first_seen=datetime.utcfromtimestamp(
                    #             int(misp_sighting["date_sighting"])
                    #         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    #         last_seen=datetime.utcfromtimestamp(
                    #             int(misp_sighting["date_sighting"])
                    #         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    #         where_sighted_refs=[sighted_by]
                    #         if sighted_by is not None
                    #         else None,
                    #     )
                    #     sightings.append(sighting)

            ### Create the relationships
            relationships = []
            if not create_relationships:
                return {
                    "indicator": indicator,
                    "observable": observable,
                    "relationships": relationships,
                    "attribute_elements": attribute_elements,
                    "markings": attribute_markings,
                    "identities": identities,
                    "sightings": sightings,
                }
            if indicator is not None and observable is not None:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", indicator.id, observable.id
                        ),
                        relationship_type="based-on",
                        created_by_ref=author["id"],
                        source_ref=indicator.id,
                        target_ref=observable.id,
                        allow_custom=True,
                    )
                )
            ### Create relationship between MISP attribute (indicator or observable) and MISP object (observable)
            if object_observable is not None and (
                indicator is not None or observable is not None
            ):
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            object_observable.id,
                            observable.id if observable is not None else indicator.id,
                        ),
                        relationship_type="related-to",
                        created_by_ref=author["id"],
                        source_ref=object_observable.id,
                        target_ref=(
                            observable.id if (observable is not None) else indicator.id
                        ),
                        allow_custom=True,
                    )
                )
            # Event threats
            threat_names = {}
            for threat in (
                event_elements["intrusion_sets"]
                + event_elements["malwares"]
                + event_elements["tools"]
            ):
                threat_names[threat.name] = threat.id
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "indicates", indicator.id, threat.id
                            ),
                            relationship_type="indicates",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, threat.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )

            # Attribute threats
            for threat in (
                attribute_elements["intrusion_sets"]
                + attribute_elements["malwares"]
                + attribute_elements["tools"]
            ):
                if threat.name in threat_names:
                    threat_id = threat_names[threat.name]
                else:
                    threat_id = threat.id
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "indicates", indicator.id, threat_id
                            ),
                            relationship_type="indicates",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=threat_id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, threat_id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=threat_id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
            # Event Attack Patterns
            for attack_pattern in event_elements["attack_patterns"]:
                if len(event_elements["malwares"]) > 0:
                    threats = event_elements["malwares"]
                elif len(event_elements["intrusion_sets"]) > 0:
                    threats = event_elements["intrusion_sets"]
                else:
                    threats = []
                for threat in threats:
                    if threat.name in threat_names:
                        threat_id = threat_names[threat.name]
                    else:
                        threat_id = threat.id
                    relationship_uses = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", threat_id, attack_pattern.id
                        ),
                        relationship_type="uses",
                        created_by_ref=author["id"],
                        source_ref=threat_id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                    relationships.append(relationship_uses)
                    # if indicator is not None:
                    #     relationship_indicates = Relationship(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id(
                    #             "relationship"
                    #         ),
                    #         relationship_type="indicates",
                    #         created_by_ref=author["id"],
                    #         source_ref=indicator.id,
                    #         target_ref=relationship_uses.id,
                    #         description=attribute["comment"],
                    #         confidence=self.helper.connect_confidence_level,
                    #         object_marking_refs=attribute_markings,
                    #     )
                    #     relationships.append(relationship_indicates)
                    # if observable is not None:
                    #     relationship_indicates = Relationship(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id(
                    #             "relationship"
                    #         ),
                    #         relationship_type="related-to",
                    #         created_by_ref=author["id"],
                    #         source_ref=observable.id,
                    #         target_ref=relationship_uses.id,
                    #         description=attribute["comment"],
                    #         confidence=self.helper.connect_confidence_level,
                    #         object_marking_refs=attribute_markings,
                    #     )
                    #     relationships.append(relationship_indicates)

            # Attribute Attack Patterns
            for attack_pattern in attribute_elements["attack_patterns"]:
                if len(attribute_elements["malwares"]) > 0:
                    threats = attribute_elements["malwares"]
                elif len(attribute_elements["intrusion_sets"]) > 0:
                    threats = attribute_elements["intrusion_sets"]
                else:
                    threats = []
                for threat in threats:
                    if threat.name in threat_names:
                        threat_id = threat_names[threat.name]
                    else:
                        threat_id = threat.id
                    relationship_uses = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", threat_id, attack_pattern.id
                        ),
                        relationship_type="uses",
                        confidence=self.helper.connect_confidence_level,
                        created_by_ref=author["id"],
                        source_ref=threat_id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                    relationships.append(relationship_uses)
                    # if indicator is not None:
                    #    relationship_indicates = Relationship(
                    #        id=OpenCTIStix2Utils.generate_random_stix_id(
                    #            "relationship"
                    #        ),
                    #        relationship_type="indicates",
                    #        created_by_ref=author["id"],
                    #        source_ref=indicator.id,
                    #        target_ref=relationship_uses.id,
                    #        description=attribute["comment"],
                    #        confidence=self.helper.connect_confidence_level,
                    #        object_marking_refs=attribute_markings,
                    #    )
                    #    relationships.append(relationship_indicates)
                    # if observable is not None:
                    #    relationship_indicates = Relationship(
                    #        id=OpenCTIStix2Utils.generate_random_stix_id(
                    #            "relationship"
                    #        ),
                    #        relationship_type="indicates",
                    #        created_by_ref=author["id"],
                    #        source_ref=observable.id,
                    #        target_ref=relationship_uses.id,
                    #        description=attribute["comment"],
                    #        confidence=self.helper.connect_confidence_level,
                    #        object_marking_refs=attribute_markings,
                    #    )
                    #    relationships.append(relationship_indicates)
            for sector in attribute_elements["sectors"]:
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", indicator.id, sector.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=sector.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, sector.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=sector.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )

            for country in attribute_elements["countries"]:
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", indicator.id, country.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=country.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, country.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=country.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
            return {
                "indicator": indicator,
                "observable": observable,
                "relationships": relationships,
                "attribute_elements": attribute_elements,
                "markings": attribute_markings,
                "identities": identities,
                "sightings": sightings,
            }

    def _find_type_by_uuid(self, uuid, bundle_objects):
        # filter by uuid
        i_result = list(filter(lambda o: o.id.endswith("--" + uuid), bundle_objects))

        if len(i_result) > 0:
            uuid = i_result[0]["id"]
            return {
                "entity": i_result[0],
                "type": uuid[: uuid.index("--")],
            }
        return None

    # Markdown object, attribute & tag links should be converted from MISP links to OpenCTI links
    def _process_note(self, content, bundle_objects):
        def reformat(match):
            type = match.group(1)
            uuid = match.group(2)
            result = self._find_type_by_uuid(uuid, bundle_objects)
            if result is None:
                return "[{}:{}](/dashboard/search/{})".format(type, uuid, uuid)
            if result["type"] == "indicator":
                name = result["entity"]["pattern"]
            else:
                name = result["entity"]["value"]
            return "[{}:{}](/dashboard/search/{})".format(
                type, name, result["entity"]["id"]
            )

        r_object = r"@\[(object|attribute)\]\(([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\)"
        r_tag = r'@\[tag\]\(([a-zA-Z:"\'0-9\-=]+)\)'

        content = re.sub(r_object, reformat, content, flags=re.MULTILINE)
        content = re.sub(r_tag, r"tag:\1", content, flags=re.MULTILINE)
        return content

    def _process_event(self, event) -> str:
        # Check the event is a list or not
        ## It may be an illegal case if the length is not 1

        if isinstance(event, list):
            if len(event) == 1:
                event = event[0]
            else:
                raise ValueError("The list of is too long.")

        ### Default variables
        added_markings = []
        added_entities = []
        added_object_refs = []
        added_sightings = []
        added_files = []
        added_observables = []
        added_relationships = []

        ### Pre-process
        # Author
        author = None
        if self.misp_import_file_author_from_tags:
            if "Tag" in event["Event"]:
                event_tags = event["Event"]["Tag"]
                for tag in event_tags:
                    tag_name = tag["name"].lower()
                    if tag_name.startswith("creator") and "=" in tag_name:
                        author_name = tag_name.split("=")[1]
                        author = stix2.Identity(
                            id=Identity.generate_id(author_name, "organization"),
                            name=author_name,
                            identity_class="organization",
                        )
        if author is None:
            author = stix2.Identity(
                id=Identity.generate_id(event["Event"]["Orgc"]["name"], "organization"),
                name=event["Event"]["Orgc"]["name"],
                identity_class="organization",
            )
        # Markings
        if "Tag" in event["Event"]:
            event_markings = self._resolve_markings(event["Event"]["Tag"])
        else:
            event_markings = [stix2.TLP_WHITE]

        # Elements
        event_elements = self._prepare_elements(
            event["Event"].get("Galaxy", []),
            event["Event"].get("Tag", []),
            author,
            event_markings,
        )
        # Tags
        event_tags = []
        if "Tag" in event["Event"]:
            event_tags = self._resolve_tags(event["Event"]["Tag"])

        # ExternalReference
        event_external_reference = stix2.ExternalReference(
            source_name="MISP",
            description=event["Event"]["info"],
            external_id=event["Event"]["uuid"],
        )

        ### Get indicators
        event_external_references = [event_external_reference]
        indicators = []
        # Get attributes of event
        create_relationships = len(event["Event"].get("Attribute", [])) < 10000
        for attribute in event["Event"].get("Attribute", []):
            indicator = self._process_attribute(
                author,
                event_elements,
                event_markings,
                event_tags,
                None,
                [],
                attribute,
                event["Event"].get("threat_level_id", "Undefined"),
                create_relationships,
            )
            if (
                attribute["type"] == "link"
                and attribute["category"] == "External analysis"
            ):
                event_external_references.append(
                    stix2.ExternalReference(
                        source_name=attribute["category"],
                        external_id=attribute["uuid"],
                        url=attribute["value"],
                    )
                )
            if indicator is not None:
                indicators.append(indicator)

            pdf_file = self._get_pdf_file(attribute)
            if pdf_file is not None:
                added_files.append(pdf_file)

        # Get attributes of objects
        indicators_relationships = []
        objects_relationships = []
        objects_observables = []
        event_threat_level = event["Event"].get("threat_level_id", "Undefined")
        for object in event["Event"].get("Object", []):
            attribute_external_references = []
            for attribute in object["Attribute"]:
                if (
                    attribute["type"] == "link"
                    and attribute["category"] == "External analysis"
                ):
                    attribute_external_references.append(
                        stix2.ExternalReference(
                            source_name=attribute["category"],
                            external_id=attribute["uuid"],
                            url=attribute["value"],
                        )
                    )

                pdf_file = self._get_pdf_file(attribute)
                if pdf_file is not None:
                    added_files.append(pdf_file)

            object_observable = None
            if self.misp_import_file_create_object_observables:
                if (
                    self.misp_import_file_import_unsupported_observables_as_text_transparent
                ):
                    if len(object["Attribute"]) > 0:
                        value = object["Attribute"][0]["value"]
                        object_observable = CustomObservableText(
                            value=value,
                            object_marking_refs=event_markings,
                            custom_properties={
                                "description": object["description"],
                                "x_opencti_score": self._threat_level_to_score(
                                    event_threat_level
                                ),
                                "labels": event_tags,
                                "created_by_ref": author["id"],
                                "external_references": attribute_external_references,
                            },
                        )
                        objects_observables.append(object_observable)
                else:
                    unique_key = ""
                    if len(object["Attribute"]) > 0:
                        unique_key = (
                            " ("
                            + object["Attribute"][0]["type"]
                            + "="
                            + object["Attribute"][0]["value"]
                            + ")"
                        )
                    object_observable = CustomObservableText(
                        value=object["name"] + unique_key,
                        object_marking_refs=event_markings,
                        custom_properties={
                            "description": object["description"],
                            "x_opencti_score": self._threat_level_to_score(
                                event_threat_level
                            ),
                            "labels": event_tags,
                            "created_by_ref": author["id"],
                            "external_references": attribute_external_references,
                        },
                    )
                    objects_observables.append(object_observable)
            object_attributes = []
            create_relationships = len(object["Attribute"]) < 10000
            for attribute in object["Attribute"]:
                indicator = self._process_attribute(
                    author,
                    event_elements,
                    event_markings,
                    event_tags,
                    object_observable,
                    attribute_external_references,
                    attribute,
                    event["Event"].get("threat_level_id", "Undefined"),
                    create_relationships,
                )
                if indicator is not None:
                    indicators.append(indicator)
                    if (
                        indicator["indicator"] is not None
                        and object["meta-category"] == "file"
                        and indicator["indicator"].get(
                            "x_opencti_main_observable_type", "Unknown"
                        )
                        in FILETYPES
                    ):
                        object_attributes.append(indicator)
            # TODO Extend observable

        ### Prepare the bundle
        bundle_objects = [author]
        object_refs = []
        # Add event markings
        for event_marking in event_markings:
            if event_marking["id"] not in added_markings:
                bundle_objects.append(event_marking)
                added_markings.append(event_marking["id"])
        # Add event elements
        all_event_elements = (
            event_elements["intrusion_sets"]
            + event_elements["malwares"]
            + event_elements["tools"]
            + event_elements["attack_patterns"]
            + event_elements["sectors"]
            + event_elements["countries"]
        )
        for event_element in all_event_elements:
            if event_element["id"] not in added_object_refs:
                object_refs.append(event_element)
                added_object_refs.append(event_element["id"])
            if event_element["id"] not in added_entities:
                bundle_objects.append(event_element)
                added_entities.append(event_element["id"])
        # Add indicators
        for indicator in indicators:
            if indicator["indicator"] is not None:
                if indicator["indicator"]["id"] not in added_object_refs:
                    object_refs.append(indicator["indicator"])
                    added_object_refs.append(indicator["indicator"]["id"])
                if indicator["indicator"]["id"] not in added_entities:
                    bundle_objects.append(indicator["indicator"])
                    added_entities.append(indicator["indicator"]["id"])
            if indicator["observable"] is not None:
                if indicator["observable"]["id"] not in added_object_refs:
                    object_refs.append(indicator["observable"])
                    added_object_refs.append(indicator["observable"]["id"])
                if indicator["observable"]["id"] not in added_entities:
                    bundle_objects.append(indicator["observable"])
                    added_entities.append(indicator["observable"]["id"])

            # Add attribute markings
            for attribute_marking in indicator["markings"]:
                if attribute_marking["id"] not in added_markings:
                    bundle_objects.append(attribute_marking)
                    added_markings.append(attribute_marking["id"])
            # Add attribute sightings identities
            for attribute_identity in indicator["identities"]:
                if attribute_identity["id"] not in added_entities:
                    bundle_objects.append(attribute_identity)
                    added_entities.append(attribute_identity["id"])
            # Add attribute sightings
            for attribute_sighting in indicator["sightings"]:
                if attribute_sighting["id"] not in added_sightings:
                    bundle_objects.append(attribute_sighting)
                    added_sightings.append(attribute_sighting["id"])
            # Add attribute elements
            all_attribute_elements = (
                indicator["attribute_elements"]["intrusion_sets"]
                + indicator["attribute_elements"]["malwares"]
                + indicator["attribute_elements"]["tools"]
                + indicator["attribute_elements"]["attack_patterns"]
                + indicator["attribute_elements"]["sectors"]
                + indicator["attribute_elements"]["countries"]
            )
            for attribute_element in all_attribute_elements:
                if attribute_element["id"] not in added_object_refs:
                    object_refs.append(attribute_element)
                    added_object_refs.append(attribute_element["id"])
                if attribute_element["id"] not in added_entities:
                    bundle_objects.append(attribute_element)
                    added_entities.append(attribute_element["id"])
            # Add attribute relationships
            for relationship in indicator["relationships"]:
                indicators_relationships.append(relationship)

        # We want to make sure these are added as lasts, so we're sure all the related objects are created
        for indicator_relationship in indicators_relationships:
            objects_relationships.append(indicator_relationship)
        # Add MISP objects_observables
        for object_observable in objects_observables:
            if object_observable["id"] not in added_object_refs:
                object_refs.append(object_observable)
                added_object_refs.append(object_observable["id"])
            if object_observable["id"] not in added_observables:
                bundle_objects.append(object_observable)
                added_observables.append(object_observable["id"])

        # Link all objects with each other, now so we can find the correct entity type prefix in bundle_objects
        for object in event["Event"].get("Object", []):
            for ref in object.get("ObjectReference", []):
                ref_src = ref.get("source_uuid")
                ref_target = ref.get("referenced_uuid")
                if ref_src is not None and ref_target is not None:
                    src_result = self._find_type_by_uuid(ref_src, bundle_objects)
                    target_result = self._find_type_by_uuid(ref_target, bundle_objects)
                    if src_result is not None and target_result is not None:
                        objects_relationships.append(
                            stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to",
                                    src_result["entity"]["id"],
                                    target_result["entity"]["id"],
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                description="Original Relationship: "
                                + ref["relationship_type"]
                                + "  \nComment: "
                                + ref["comment"],
                                source_ref=src_result["entity"]["id"],
                                target_ref=target_result["entity"]["id"],
                                allow_custom=True,
                            )
                        )
        # Add object_relationships
        for object_relationship in objects_relationships:
            if (
                object_relationship["source_ref"] + object_relationship["target_ref"]
                not in added_object_refs
            ):
                object_refs.append(object_relationship)
                added_object_refs.append(
                    object_relationship["source_ref"]
                    + object_relationship["target_ref"]
                )
            if (
                object_relationship["source_ref"] + object_relationship["target_ref"]
                not in added_relationships
            ):
                bundle_objects.append(object_relationship)
                added_relationships.append(
                    object_relationship["source_ref"]
                    + object_relationship["target_ref"]
                )

        # Create the report if needed
        # Report in STIX must have at least one object_refs
        if self.misp_import_file_create_reports:
            # Report in STIX lib must have at least one object_refs
            if len(object_refs) == 0:
                # Put a fake ID in the report
                object_refs.append(
                    "intrusion-set--fc5ee88d-7987-4c00-991e-a863e9aa8a0e"
                )
            report = stix2.Report(
                id=Report.generate_id(
                    event["Event"]["info"],
                    datetime.utcfromtimestamp(
                        int(
                            datetime.strptime(
                                str(event["Event"]["date"]), "%Y-%m-%d"
                            ).timestamp()
                        )
                    ),
                ),
                name=event["Event"]["info"],
                description=event["Event"]["info"],
                published=datetime.utcfromtimestamp(
                    int(
                        datetime.strptime(
                            str(event["Event"]["date"]), "%Y-%m-%d"
                        ).timestamp()
                    )
                ),
                created=datetime.utcfromtimestamp(
                    int(
                        datetime.strptime(
                            str(event["Event"]["date"]), "%Y-%m-%d"
                        ).timestamp()
                    )
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                modified=datetime.utcfromtimestamp(
                    int(event["Event"]["timestamp"])
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                report_types=[self.misp_import_file_report_type],
                created_by_ref=author["id"],
                object_marking_refs=event_markings,
                labels=event_tags,
                object_refs=object_refs,
                external_references=event_external_references,
                confidence=self.helper.connect_confidence_level,
                custom_properties={
                    "x_opencti_files": added_files,
                },
                allow_custom=True,
            )
            bundle_objects.append(report)
            for note in event["Event"].get("EventReport", []):
                note = stix2.Note(
                    id=Note.generate_id(
                        datetime.utcfromtimestamp(int(note["timestamp"])).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                        self._process_note(note["content"], bundle_objects),
                    ),
                    confidence=self.helper.connect_confidence_level,
                    created=datetime.utcfromtimestamp(int(note["timestamp"])).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    modified=datetime.utcfromtimestamp(int(note["timestamp"])).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    created_by_ref=author["id"],
                    object_marking_refs=event_markings,
                    abstract=note["name"],
                    content=self._process_note(note["content"], bundle_objects),
                    object_refs=[report],
                    allow_custom=True,
                )
                bundle_objects.append(note)
        return stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()

    def _process_message(self, data):
        file_fetch = data["file_fetch"]
        bypass_validation = data["bypass_validation"]
        file_markings = data.get("file_markings", [])
        file_uri = self.helper.opencti_url + file_fetch
        self.helper.log_info(f"Importing the file {file_uri}")
        file_content = self.helper.api.fetch_opencti_file(file_uri)
        events = json.loads(file_content)
        if not isinstance(events, list):
            if "response" in events:
                events = events["response"]
            else:
                events = [events]
        bundles_sent = 0
        for event in events:
            bundle_json = self._process_event(event)
            entity_id = data.get("entity_id", None)
            if entity_id:
                self.helper.log_info("Contextual import.")
                bundle = json.loads(bundle_json)["objects"]
                bundle = self._update_container(bundle, entity_id)
                bundle_json = self.helper.stix2_create_bundle(bundle)
            bundles_sent_event = self.helper.send_stix2_bundle(
                bundle_json,
                bypass_validation=bypass_validation,
                file_name=data["file_id"],
                entity_id=entity_id,
                file_markings=file_markings,
            )
            bundles_sent = bundles_sent + len(bundles_sent_event)
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(bundles_sent) + " generated bundle(s) for worker import"

    def start(self):
        self.helper.listen(self._process_message)

    @staticmethod
    def _is_container(element_type: str):
        return (
            element_type == "report"
            or element_type == "grouping"
            or element_type == "observed-data"
            or element_type == "x-opencti-case-incident"
            or element_type == "x-opencti-case-rfi"
            or element_type == "x-opencti-case-rft"
            or element_type == "x-opencti-task"
            or element_type == "x-opencti-feedback"
        )

    def _contains_container(self, bundle) -> bool:
        for elem in bundle:
            if self._is_container(elem.get("type")):
                return True
        return False

    def _update_container(self, bundle, entity_id):
        container = self.helper.api.stix_domain_object.read(id=entity_id)
        container_stix_bundle = (
            self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type=container["entity_type"], entity_id=container["id"]
            )
        )
        if len(container_stix_bundle["objects"]) > 0:
            container_stix = [
                object
                for object in container_stix_bundle["objects"]
                if "x_opencti_id" in object
                and object["x_opencti_id"] == container["id"]
            ][0]
            if self._is_container(container_stix.get("type")):
                if self._contains_container(bundle):
                    self.helper.log_info("Bundle contains container.")
                    container_stix["object_refs"] = []
                    for elem in bundle:
                        if self._is_container(elem.get("type")):
                            container_stix["object_refs"].append(elem["id"])
                            if "object_refs" in elem:
                                for object_id in elem.get("object_refs"):
                                    container_stix["object_refs"].append(object_id)
                else:
                    self.helper.log_info(
                        "No container in Stix file. Updating current container"
                    )
                    container_stix["object_refs"] = [object["id"] for object in bundle]
                bundle.append(container_stix)
        return bundle


if __name__ == "__main__":
    try:
        mispImportFileConnector = MispImportFile()
        mispImportFileConnector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
