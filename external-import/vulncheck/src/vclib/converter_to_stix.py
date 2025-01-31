import ipaddress
from datetime import datetime

import stix2
import validators
from pycti import (
    Identity,
    Indicator,
    Infrastructure,
    Location,
    Malware,
    StixCoreRelationship,
    ThreatActorGroup,
    Vulnerability,
)


class ConverterToStix:
    """Provides methods for converting various types of input data into STIX 2.1 objects.

    Class Attributes:
    - author (stix2.Identity): Author Object
    - external_reference (stix2.ExternalReference): External Reference Object

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author_vc()
        self.external_reference = self.create_external_reference_vc()

    @staticmethod
    def create_external_reference_vc() -> list[stix2.ExternalReference]:
        """Create external reference

        Returns:
            stix2.ExternalReference: External Reference Object
        """
        external_reference = stix2.ExternalReference(
            source_name="VulnCheck",
            url="https://vulncheck.com/",
            description="VulnCheck helps organizations outpace adversaries with vulnerability intelligence that predicts avenues of attack with speed and accuracy.",
        )
        return [external_reference]

    @staticmethod
    def create_author_vc() -> stix2.Identity:
        """Create Author

        Returns:
            stix2.Identity: Author Object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="VulnCheck", identity_class="organization"),
            name="VulnCheck",
            identity_class="organization",
            description="Unprecedented visibility into the vulnerability ecosystem from the eye of the storm. Prioritize response. Finish taking action before the attacks occur.",
            object_marking_refs=[stix2.TLP_WHITE],
        )
        return author

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> stix2.Relationship:
        """Creates Relationship object

        Args:
            source_id (str): Source ID
            relationship_type (str): Relationship Type
            target_id (str): Target ID

        Returns:
            stix2.Relationship: Relationship Object

        Examples:
            >>> create_relationship(malware["id], "targets", vulnerability["id"])
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            external_references=self.external_reference,
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return relationship

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """Determine whether the provided IP string is IPv6

        Args:
            value (str): Value in string

        Returns:
            bool: True if the value is a valid IPv6 address, False otherwise

        Examples:
            >>> _is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """Check if the value is a valid domain name

        Args:
            value (str): Value

        Returns:
            bool: True if the value is a valid domain name, False otherwise

        Examples:
            >>> _is_domain("example.com")
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def create_obs(self, value: str):
        """Create Observable Object

        Args:
            value (str): Observable Value

        Returns:
            stix2.IPv6Address or stix2.IPv4Address or stix2.DomainName: Observable Object

        Examples:
            >>> create_obs("1.1.1.1")
        """
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                value=value,
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                value=value,
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                value=value,
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                    "x_opencti_external_references": self.external_reference,
                },
            )
            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )

    def create_infrastructure(
        self,
        name: str,
        infrastructure_type: str,
        last_seen=None,
    ) -> stix2.Infrastructure:
        """Create Infrastructure Object

        Args:
            name (str): Infrastructure Name
            last_seen (datetime): Last Seen Date

        Returns:
            stix2.Infrastructure: Infrastructure Object

        Examples:
            >>> create_infrastructure("APT1", datetime.now)
        """
        stix_infrastructure = stix2.Infrastructure(
            id=Infrastructure.generate_id(name),
            name=name,
            infrastructure_types=[infrastructure_type],
            created_by_ref=self.author,
            last_seen=last_seen,
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return stix_infrastructure

    def create_location(self, country_name: str, country_code: str) -> stix2.Location:
        """Create Location Object

        Args:
            country_name (str): Country Name
            country_code (str): Country Code

        Returns:
            stix2.Location: Location Object

        Examples:
            >>> create_location("United States", "US")
        """
        stix_location = stix2.Location(
            id=Location.generate_id(country_name, "Country"),
            name=country_name,
            created_by_ref=self.author,
            country=country_code,
            custom_properties={"x_opencti_location_type": "Country"},
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return stix_location

    def create_vulnerability(
        self,
        cve: str,
        custom_properties: dict = {},
    ) -> stix2.Vulnerability:
        """Create Vulnerability Object

        Args:
            cve (str): Common Vulnerabilities and Exposures

        Returns:
            stix2.Vulnerability: Vulnerability Object

        Examples:
            >>> create_vulnerability("CVE-2021-1234")
        """
        external_ref = self.create_external_reference(
            source_name=f"VulnCheck {cve}",
            url=f"https://vulncheck.com/cve/{cve}",
        )
        stix_vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(cve),
            name=cve,
            created_by_ref=self.author,
            external_references=[external_ref],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties=custom_properties,
        )
        return stix_vulnerability

    def create_malware(
        self,
        name: str,
        is_family: bool,
        first_seen: datetime,
        description: str = "",
    ) -> stix2.Malware:
        """Create Malware Object

        Args:
            name (str): Malware Name
            description (str): Description
            is_family (bool): Is Family
            first_seen (datetime): First Seen Date

        Returns:
            stix2.Malware: Malware Object

        Examples:
            >>> create_malware("WannaCry", "Ransomware", True, datetime.now())
        """
        malware = stix2.Malware(
            id=Malware.generate_id(name),
            name=name,
            description=description,
            is_family=is_family,
            first_seen=first_seen,
            created_by_ref=self.author,
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return malware

    def create_software(
        self, product: str, vendor: str, version: str, cpe: str
    ) -> stix2.Software:
        """Create Software Object

        Args:
            name (str): Software Name
            vendor (str): Vendor Name
            cpe (str): Common Platform Enumeration

        Returns:
            stix2.Software: Software Object

        Examples:
            >>> create_software("Windows", "Microsoft", "1.0" "cpe:/o:microsoft:windows")
        """
        software = stix2.Software(
            name=f"{vendor} {product}",
            vendor=vendor,
            version=version,
            cpe=cpe,
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return software

    def create_external_reference(
        self, source_name: str, url: str
    ) -> stix2.ExternalReference:
        """Create External Reference Object

        Args:
            source_name (str): Source Name
            url (str): URL

        Returns:
            stix2.ExternalReference: External Reference Object

        Examples:
            >>> create_external_reference("VulnCheck", "https://vulncheck.com/")
        """
        external_reference = stix2.ExternalReference(
            source_name=source_name,
            url=url,
        )
        return external_reference

    def create_threat_actor_group(
        self, name: str, first_seen: datetime, external_refs: list
    ) -> stix2.ThreatActor:
        """Create a Threat Actor Group Object

        Args:
            name (str): Threat Actor Group Name
            first_seen (datetime): First Seen Date
            external_refs (list): List of External References

        Returns:
            stix2.ThreatActor: Threat Actor Group Object

        Examples:
            >>> create_threat_actor_group("APT1", datetime.now(), [external_ref1, external_ref2])
        """
        threat_actor = stix2.ThreatActor(
            id=ThreatActorGroup.generate_id(name),
            name=name,
            first_seen=first_seen,
            external_references=external_refs,
            created_by_ref=self.author,
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return threat_actor

    def create_indicator(
        self, pattern: str, pattern_type: str, name: str, description: str
    ) -> stix2.Indicator:
        """Create an Indicator Object

        Args:
            pattern (str): Rule Pattern
            pattern_type (str): Rule Pattern Type
            name (str): Rule Name
            description (str): Rule Description

        Returns:
            stix2.Indicator: Indicator STIX Object

        Examples:
            >>> create_indicator("rule-test", "snort", "rule name", "rule description")
        """
        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self.author,
            pattern=pattern,
            pattern_type=pattern_type,
            name=name,
            description=description,
            object_marking_refs=[stix2.TLP_AMBER],
        )
        return indicator
