"""
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Group-IB makes no              #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Group-IB shall not be liable for, and you assume all risk of                 #
# using the foregoing.                                                         #
################################################################################
Author: Pavel Reshetnikov, Integration developer, 2024
"""

import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse

import pycti  # type: ignore
import stix2
from config import ConfigConnector


class ConversionError(Exception):
    """Generic exception for stix2 conversion issues"""

    pass


class _CommonUtils:

    @staticmethod
    def _sanitize(message):
        # type: (str) -> str
        """Sanitize message"""
        # Use repr to suppress \t, \n, \r, and strip the surrounding quotes added by repr.
        return repr(message)[1:-1]

    @staticmethod
    def _remove_html_tags(message):
        """Remove html tags from a string"""
        clean = re.compile("<.*?>")
        return re.sub(clean, "", message)

    @staticmethod
    def _extract_domain(url, suffix=""):
        # type: (str, str) -> str
        """Extract domain name from url"""
        parsed_url = urlparse(url)
        if parsed_url.path and parsed_url.path != "/":
            return parsed_url.netloc + suffix
        return parsed_url.netloc

    @staticmethod
    def is_ipv4(ipv4):
        # type: (str) -> bool
        """Determine whether the provided IP string is IPv4."""
        try:
            ipaddress.IPv4Address(ipv4)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_ipv6(ipv6):
        # type: (str) -> bool
        """Determine whether the provided IP string is IPv6."""
        try:
            ipaddress.IPv6Address(ipv6)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def determine_hash_algorithm_by_length(file_hash):
        """Determine file hash algorithm from length"""
        if len(file_hash) == 64:
            return "SHA-256"
        elif len(file_hash) == 40:
            return "SHA-1"
        elif len(file_hash) == 32:
            return "MD5"
        msg = f"Could not determine hash type for {file_hash}. Only MD5, SHA1 and SHA256 hashes are supported"
        raise ValueError(msg)

    @staticmethod
    def _generate_tlp_obj(color):
        # type: (str) -> Any
        """Generate TLP object"""
        return ConfigConnector.STIX_TLP_MAP.get(color.lower())

    @staticmethod
    def _generate_main_observable_type(obj_type):
        # type: (str) -> str
        """Generate TLP object"""
        return ConfigConnector.STIX_MAIN_OBSERVABLE_TYPE_MAP.get(obj_type)

    @staticmethod
    def _generate_malware_type(obj_type):
        # type: (str) -> Optional[str, None]
        """Generate Malware type object"""
        if obj_type.lower() in ConfigConnector.STIX_MALWARE_TYPE_MAP:
            return obj_type.lower()
        else:
            return None

    @staticmethod
    def _generate_country_by_cc(country_code):
        # type: (str) -> str
        """Generate Country by Country Code"""
        return ConfigConnector.COUNTRIES.get(country_code)

    @staticmethod
    def _generate_stix_country_type(country_type):
        # type: (str) -> str
        """Generate STIX2 Country type by Country type"""
        return ConfigConnector.COUNTRIES.get(country_type)

    @staticmethod
    def _generate_stix_report_type(report_type):
        # type: (str) -> str
        """Generate STIX2 Report type by Report type"""
        return ConfigConnector.STIX_REPORT_TYPE_MAP.get(report_type)


class BaseEntity(_CommonUtils):

    def __init__(self, name, c_type, tlp_color):
        self.name = name
        self.c_type = c_type
        self.author = self._generate_author()
        self.tlp = self._generate_tlp_obj(tlp_color)
        self.is_ioc = False
        self.description = ""

        self.valid_from: datetime = datetime.now()
        self.valid_until: datetime = datetime.now()

        # defined in self._setup
        self.stix_indicator = None
        self.stix_observable = None
        self.stix_sdo = None
        self.stix_common = None
        self.stix_relationships = list()

        self.external_references = list()

        self.stix_main_object = None
        self.stix_objects = None

    @staticmethod
    def _generate_author():
        """Generate Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id(ConfigConnector.AUTHOR, "organization"),
            name=ConfigConnector.AUTHOR,
            identity_class="organization",
        )

    def _generate_indicator(self):
        return

    def _generate_observable(self):
        return

    def _generate_sdo(self):
        return

    def _generate_common(self):
        return

    def set_description(self, text):
        # type: (str) -> None
        """Set object description"""
        if text:
            self.description = self._remove_html_tags(self._sanitize(text))

    def set_valid_from(self, date):
        # type: (datetime) -> None
        """Set object valid_from"""
        if date:
            self.valid_from = date

    def set_valid_until(self, date):
        # type: (datetime) -> None
        """Set object valid_until"""
        if date:
            self.valid_until = date

    def _generate_relationship(self, source_id, target_id, relation_type="based-on"):
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relation_type, source_id, target_id
            ),
            relationship_type=relation_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
        )

    def generate_relationship(
        self, source_object, target_object, relation_type="based-on"
    ):
        # type: (Any, Any, str) -> None

        self.stix_relationships.append(
            self._generate_relationship(
                source_object.id, target_object.id, relation_type
            )
        )

    def _generate_external_reference(self, ref_id, ref_url, ref_desc):
        return stix2.ExternalReference(
            external_id=pycti.ExternalReference.generate_id(
                ref_url, self._extract_domain(ref_url), ref_id
            ),
            # source_name=self._extract_domain(ref_url),
            source_name=ref_desc.split(" - ")[0],
            url=ref_url,
            description=ref_desc,
        )

    def generate_external_references(self, reference_objects):
        # type: (List[Tuple[str, str, str]]) -> List[stix2.ExternalReference]
        """
        Generate STIX ExternalReference objects from object attributes

        Examples:
            [(reference_id, reference_url, reference_description)]

            [
                (
                    "349585fa33dd9117622e676d69c4d286fb68b4d3",
                    "https://tap.group-ib.com/ta/last-threats?threat=349585fa33dd9117622e676d69c4d286fb68b4d3",
                    "TI Portal external reference"
                )
            ]
        """
        if reference_objects:
            self.external_references = [
                self._generate_external_reference(ref_id, ref_url, ref_desc)
                for ref_id, ref_url, ref_desc in reference_objects
            ]
        else:
            self.external_references = []
        return self.external_references

    def generate_stix_objects(self):
        """Generate STIX objects from object attributes"""
        self.stix_observable = self._generate_observable()
        self.stix_sdo = self._generate_sdo()
        self.stix_common = self._generate_common()
        if self.is_ioc:
            self.stix_indicator = self._generate_indicator()
            if isinstance(self.stix_indicator, list):
                self.stix_objects = [
                    _
                    for _ in [
                        self.stix_observable,
                        self.stix_sdo,
                        self.stix_common,
                    ]
                    if _
                ]
                self.stix_objects += self.stix_indicator
            else:
                self.stix_objects = [
                    _
                    for _ in [
                        self.stix_indicator,
                        self.stix_observable,
                        self.stix_sdo,
                        self.stix_common,
                    ]
                    if _
                ]
            return self
        else:
            self.stix_objects = [
                _
                for _ in [
                    self.stix_observable,
                    self.stix_sdo,
                    self.stix_common,
                ]
                if _
            ]
            return self

    def add_relationships_to_stix_objects(self):
        """Append relationships to STIX objects"""
        if self.stix_relationships:
            self.stix_objects += self.stix_relationships
        return self.stix_objects

    def bundle(self):
        """Generate Bundle of STIX objects"""
        return stix2.Bundle(objects=self.stix_objects, allow_custom=True)


class _BaseIndicator(BaseEntity):
    """
    Base class for Indicators of Compromise (IP, Hash, URL, Domain)

    autostart
    1. _generate_indicator
    2. _generate_observable

    3.
    """

    def __init__(self, name, c_type, tlp_color, labels, risk_score):
        # type: (str, str, str, List[str], Union[None, str]) -> None
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score

    def _create_pattern(self, pattern_name):
        return

    def _generate_indicator(self):
        """Creates and returns STIX2 indicator object"""
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self.name),
            name=self.name,
            description=self.description,
            pattern_type="stix",
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            pattern=self._create_pattern(self.name),
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_main_observable_type": self._generate_main_observable_type(
                    self.c_type
                ),
                "x_opencti_labels": self.labels,
            },
        )


class Indicator(_BaseIndicator):
    """Converts Indicator to STIX2 indicator"""

    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        context=None,
        created=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.context = context
        self.created = created

    def _create_pattern(self, pattern_name):
        if pattern_name == "yara":
            return self.context
        elif pattern_name == "suricata":
            return self.context
        else:
            msg = f"This pattern value {pattern_name} is not a valid."
            raise ValueError(msg)

    def _generate_indicator(self):
        """Creates and returns STIX2 indicator object"""
        self.stix_main_object = stix2.Indicator(
            id=pycti.Indicator.generate_id(self.name),
            name=self.name,
            description=self.description,
            pattern=self._create_pattern(self.c_type),
            pattern_type=self.c_type,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            created=self.created,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_main_observable_type": self._generate_main_observable_type(
                    self.c_type
                ),
                "x_opencti_labels": self.labels,
            },
        )
        return self.stix_main_object


class FileHash(_BaseIndicator):
    """Converts Hash to STIX2 File indicator and observable"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        # type: (list, str, str, List[str], Union[None, str]) -> None
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name):
        return f"[file:hashes.'{self.determine_hash_algorithm_by_length(pattern_name)}' = '{pattern_name}']"

    def _generate_observable(self):
        self.stix_main_object = stix2.File(
            hashes={
                self.determine_hash_algorithm_by_length(_name): _name
                for _name in self.name
                if _name
            },
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object

    def _generate_indicator(self):
        """Creates and returns STIX2 indicator object"""
        return [
            stix2.Indicator(
                id=pycti.Indicator.generate_id(_name),
                name=_name,
                description=self.description,
                pattern_type="stix",
                valid_from=self.valid_from,
                valid_until=self.valid_until,
                pattern=self._create_pattern(_name),
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp],
                custom_properties={
                    "x_opencti_score": self.risk_score or None,
                    "x_opencti_main_observable_type": self._generate_main_observable_type(
                        self.c_type
                    ),
                    "x_opencti_labels": self.labels,
                },
            )
            for _name in self.name
            if _name
        ]


class IPAddress(_BaseIndicator):
    """Converts IP address to STIX2 IP indicator and observable"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name):
        if self.is_ipv4(pattern_name):
            return f"[ipv4-addr:value = '{pattern_name}']"
        elif self.is_ipv6(pattern_name):
            return f"[ipv6-addr:value = '{pattern_name}']"
        else:
            msg = f"This pattern value {pattern_name} is not a valid IPv4 address."
            raise ValueError(msg)

    def _generate_observable(self):
        self.stix_main_object = stix2.IPv4Address(
            value=self.name,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object


class URL(_BaseIndicator):
    """Converts URL to STIX2 URL indicator and observable"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name):
        return f"[url:value = '{pattern_name}']"

    def _generate_observable(self):
        self.stix_main_object = stix2.URL(
            value=self.name,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object


class Domain(_BaseIndicator):
    """Converts URL to STIX2 URL indicator and observable"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name):
        return f"[domain-name:value = '{pattern_name}']"

    def _generate_observable(self):
        self.stix_main_object = stix2.DomainName(
            value=self.name,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object


class Email(_BaseIndicator):
    """Converts Email to STIX2 Email indicator and observable"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name):
        return f"[email-addr:value = '{pattern_name}']"

    def _generate_observable(self):
        self.stix_main_object = stix2.EmailAddress(
            value=self.name,
            display_name=self.name,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object


class _BaseSDO(BaseEntity):
    def __init__(self, name, c_type, tlp_color, labels, risk_score):
        # type: (str, str, str, List[str], Union[None, str]) -> None
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score


class ThreatActor(_BaseSDO):
    """Converts Threat Actor to STIX2 Threat Actor SDO"""

    def __init__(
        self,
        name,
        c_type,
        global_label,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        first_seen=None,
        last_seen=None,
        goals=None,
        roles=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.global_label = global_label
        self.aliases = aliases
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.goals = goals
        self.roles = roles

    def _generate_sdo(self):
        self.stix_main_object = stix2.ThreatActor(
            id=pycti.ThreatActorGroup.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            roles=self.roles,
            created_by_ref=self.author.id,
            threat_actor_types=[self.global_label],
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
            },
        )
        return self.stix_main_object


class IntrusionSet(_BaseSDO):
    """Converts Intrusion Set to STIX2 Intrusion Set SDO"""

    def __init__(
        self,
        name,
        c_type,
        global_label,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        first_seen=None,
        last_seen=None,
        goals=None,
        roles=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        # self.global_label = global_label
        self.aliases = aliases
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.goals = goals
        # self.roles = roles

    def _generate_sdo(self):
        self.stix_main_object = stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            # roles=self.roles,
            created_by_ref=self.author.id,
            # threat_actor_types=[self.global_label],
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
            },
        )
        return self.stix_main_object


class Malware(_BaseSDO):
    """Converts Malware to STIX2 Malware SDO"""

    def __init__(
        self,
        name,
        c_type,
        malware_types,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        last_seen=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.malware_types = []
        if malware_types:
            self.malware_types = [
                self._generate_malware_type(_t) for _t in malware_types
            ]
        self.aliases = aliases
        self.last_seen = last_seen

    def _generate_sdo(self):
        self.stix_main_object = stix2.Malware(
            id=pycti.Malware.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            last_seen=self.last_seen,
            malware_types=self.malware_types or ["unknown"],
            is_family=False,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
            },
        )
        return self.stix_main_object


class Vulnerability(_BaseSDO):
    """Converts Vulnerability to STIX2 Vulnerability SDO"""

    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        created=None,
        modified=None,
        cvss_score=None,
        cvss_vector=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.created = created
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        """
        CVSSv2:
            "0-3.9": "LOW"
            "4.0-6.9": "MEDIUM"
            "7.0-10.0": "HIGH"
        CVSSv3:
            "0.1-3.9": "LOW"
            "4.0-6.9": "MEDIUM"
            "7.0-8.9": "HIGH"
            "9.0-10.0": "CRITICAL"
        """
        if self.cvss_score:
            if 0 <= self.cvss_score <= 3.9:
                self.cvss_severity = "LOW"
            elif 4.0 <= self.cvss_score <= 6.9:
                self.cvss_severity = "MEDIUM"
            elif 7.0 < self.cvss_score <= 8.9:
                self.cvss_severity = "HIGH"
            elif 9.0 < self.cvss_score <= 10.0:
                self.cvss_severity = "CRITICAL"
            else:
                self.cvss_severity = None
        else:
            self.cvss_severity = None

    def _generate_sdo(self):
        self.stix_main_object = stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            description=self.description,
            created=self.created,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
                "x_opencti_cvss_base_score": self.cvss_score,
                "x_opencti_cvss_base_severity": self.cvss_severity,
                "x_opencti_cvss_attack_vector": self.cvss_vector,
            },
        )
        return self.stix_main_object


class AttackPattern(_BaseSDO):
    """Converts AttackPattern to STIX2 AttackPattern SDO"""

    def __init__(
        self,
        name,
        c_type,
        kill_chain_phases,
        mitre_id,
        tlp_color="white",
        labels=None,
        risk_score=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.kill_chain_phases = kill_chain_phases
        self.mitre_id = mitre_id

    def _generate_sdo(self):
        self.stix_main_object = stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(self.name, self.mitre_id),
            name=self.name,
            kill_chain_phases=self.kill_chain_phases,
            description=self.description,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
                "x_mitre_id": self.mitre_id,
            },
        )
        return self.stix_main_object


class Report(_BaseSDO):
    """Converts AttackPattern to STIX2 AttackPattern SDO"""

    def __init__(
        self,
        name,
        c_type,
        published_time,
        related_objects_ids,
        tlp_color="white",
        labels=None,
        risk_score=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.published_time = published_time or datetime.now()
        self.related_objects_ids = related_objects_ids

    def _generate_sdo(self):
        self.stix_main_object = stix2.Report(
            id=pycti.Report.generate_id(self.name, self.published_time),
            name=self.name,
            description=self.description,
            published=self.published_time,
            report_types=[self._generate_stix_report_type(self.c_type)],
            object_refs=self.related_objects_ids,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
            },
        )
        return self.stix_main_object


class _BaseCommon(BaseEntity):
    def __init__(self, name, c_type, tlp_color, labels, risk_score):
        # type: (str, str, str, List[str], Union[None, str]) -> None
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score


class Location(_BaseCommon):
    """Converts Location to STIX2 Location SDO"""

    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        location_type="Country",
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.location_type = location_type

    def _generate_common(self):
        self.stix_main_object = stix2.Location(
            id=pycti.Location.generate_id(
                self._generate_country_by_cc(self.name), self.location_type
            ),
            name=self._generate_country_by_cc(self.name),
            description=self.description,
            country=self.name,
            object_marking_refs=[self.tlp],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
                "x_opencti_aliases": self.name,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object


class KillChainPhase(_BaseCommon):
    """Converts KillChainPhase to STIX2 KillChainPhase SDO"""

    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _generate_common(self):
        self.stix_main_object = stix2.KillChainPhase(
            kill_chain_name=self.name,
            phase_name=self.c_type,
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_opencti_external_references": self.external_references,
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object
