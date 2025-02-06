from datetime import datetime

from connector.models import (
    Asn,
    Author,
    DomainName,
    File,
    IPAddress,
    Location,
    MarkingDefinition,
    Relationship,
)
from pycti import OpenCTIConnectorHelper


class ConverterToStix:

    def __init__(self, helper: OpenCTIConnectorHelper):
        """Initializes the `ConverterToStix` class.

        Args:
            helper (OpenCTIConnectorHelper): The OpenCTI connector helper instance.
        """
        self.helper = helper
        self._author = self.make_author()
        self._tlp_amber_strict = self.make_marking_definition_tlp_amber_strict()

    def make_author(self) -> Author:
        """Make an Author object and its representation in STIX 2.1 format.
        The author represents ProofPoint as the source of the reputation data.

        Returns:
            Author: A Author object and its representation in STIX 2.1 format.
        """
        return Author(
            name=self.helper.connector.name,
            organization_type="vendor",
            description="The ET Intelligence API is organized around REST with JSON responses. Our API is designed to use HTTP response codes to indicate API success/errors. We support cross-origin resource sharing (CORS) to allow you to interact with our API from a client-side web application. JSON will be returned in all responses from the API. The ET Intelligence API can be used to get information such as up-to-date reputation of domains and IPs, as well as related information on our entire database of over 300 million malware samples.We currently have code examples using curl and Python. If you have a particular language you'd like to see API examples for, please let us know. You can view code examples in the dark area to the right, and you can switch the programming language of the examples with the tabs in the top right.",
        )

    @staticmethod
    def make_marking_definition_tlp_amber_strict() -> MarkingDefinition:
        """Creates a TLP:AMBER+STRICT marking definition object and its representation in STIX 2.1 format.
        This marking is used to classify the confidentiality level of the data.

        Returns:
            MarkingDefinition: A TLP:AMBER+STRICT marking definition object and its representation in STIX 2.1 format.
        """
        return MarkingDefinition(
            definition_type="TLP",
            definition="TLP:AMBER+STRICT",
        )

    def make_relationship(
        self,
        source_object: IPAddress | DomainName | File,
        relationship_type: str,
        target_object: IPAddress | DomainName | File,
        start_time: datetime = None,
    ) -> Relationship:
        """Creates a relationship object and its representation in STIX 2.1 format.

        Args:
            source_object (Indicator): The source object.
            relationship_type (str): The type of the relationship.
            target_object (IPAddress | DomainName): The target object.
            start_time
        Returns:
            Relationship: A relationship object and its representation in STIX 2.1 format.
        """
        return Relationship(
            relationship_type=relationship_type,
            source=source_object,
            target=target_object,
            start_time=start_time,
            markings=[self._tlp_amber_strict],
            created_by=self._author,
        )

    def make_ip(self, main_entity, stix_entity: dict, labels: list[str] = None):
        """This method creates IP Address in Stix2 format.

        Args:
            main_entity:
            stix_entity:
            labels:

        Returns:

        """
        value = stix_entity.get("value", stix_entity.get("ip"))
        return IPAddress(
            value=value,
            markings=[] if main_entity else [self._tlp_amber_strict],
            labels=labels,
            created_by=self._author,
        )

    def make_domain(
        self, main_entity: bool, stix_entity: dict, labels: list[str] = None
    ):
        """This method creates Domain Name in Stix2 format.

        Args:
            main_entity:
            stix_entity:
            labels:

        Returns:

        """
        value = stix_entity.get("value", stix_entity.get("domain"))
        return DomainName(
            value=value,
            markings=[] if main_entity else [self._tlp_amber_strict],
            labels=labels,
            created_by=self._author,
        )

    def make_file(
        self, main_entity: bool, stix_entity: dict, file_details: dict = None
    ):
        """This method creates File in Stix2 format.

        Args:
            main_entity:
            stix_entity:
            file_details:

        Returns:

        """
        hash_md5 = None
        hash_sha256 = None
        if "hashes" in stix_entity:
            hash_md5 = stix_entity.get("hashes").get("MD5")
            hash_sha256 = file_details.get("sha256")
        elif "source" in stix_entity:
            hash_md5 = stix_entity.get("source")
        return File(
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            size=file_details.get("file_size") if file_details else None,
            markings=[] if main_entity else [self._tlp_amber_strict],
            created_by=self._author,
        )

    def make_location(self, location_details: dict):
        """This method creates Location country in Stix2 format.

        Args:
            location_details:

        Returns:

        """

        return Location(
            country_name=location_details.get("country"),
            country_code=location_details.get("country_code"),
            region=location_details.get("region"),
            city=location_details.get("city"),
            latitude=location_details.get("latitude"),
            longitude=location_details.get("longitude"),
            markings=[self._tlp_amber_strict],
            created_by=self._author,
        )

    def make_asn(self, asn_details: dict):
        """This method creates Anonymous System in Stix2 format.

        Args:
            asn_details:

        Returns:

        """
        return Asn(
            name=asn_details.get("owner"),
            number=asn_details.get("asn"),
            markings=[self._tlp_amber_strict],
            created_by=self._author,
        )
