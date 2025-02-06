from csv import DictReader
from datetime import datetime
from ipaddress import AddressValueError, ip_address

from dateutil.parser import parse
from pycti import StixCoreRelationship
from stix2 import (
    TLP_GREEN,
    DomainName,
    Identity,
    Indicator,
    IPv4Address,
    IPv6Address,
    Relationship,
)

DEFAULT_CONFIDENCE_LEVEL = 50
DEFAULT_TLP = TLP_GREEN


class ConverterToStix:
    """
    Provides methods for converting various Bambenek IOCs format into STIX 2.1 objects.
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.collection_to_stix_function = {
            "c2_dga": self.convert_domain_ioc_to_stix,
            "c2_dga_high_conf": self.convert_domain_ioc_to_stix,
            "c2_domain": self.convert_domain_ioc_to_stix,
            "c2_domain_highconf": self.convert_domain_ioc_to_stix,
            "c2_ip": self.convert_ip_ioc_to_stix,
            "c2_ip_highconf": self.convert_ip_ioc_to_stix,
        }

    @staticmethod
    def create_author() -> Identity:
        """
        Create Author.
        :return: Author as STIX 2.1 Identity object
        """
        author = Identity(
            id=Identity.generate_id(name="Bambenek", identity_class="organization"),
            name="Bambenek",
            identity_class="organization",
        )
        return author

    def _create_stix_indicator(
        self,
        pattern_value: str,
        name: str,
        observable_type: str,
        confidence_level: int = DEFAULT_CONFIDENCE_LEVEL,
        labels: list[str] = None,
        valid_from: datetime = None,
    ) -> Indicator:
        """
        Convenience method to return an indicator using common patterns from the Bambenek feeds
        """
        return Indicator(
            id=Indicator.generate_id(pattern_value),
            name=name,
            description="",
            created_by_ref=self.author["id"],
            confidence=confidence_level,
            pattern_type="stix",
            labels=labels,
            # The only date provided from the feed is fetch_date
            valid_from=valid_from,
            created=valid_from,
            pattern=pattern_value,
            external_references=[],
            object_marking_refs=[DEFAULT_TLP],
            custom_properties={
                "x_opencti_score": confidence_level,
                "x_opencti_main_observable_type": observable_type,
            },
        )

    @staticmethod
    def _csv_strings_to_dict(entities: list[str], fieldnames: list[str]) -> list[dict]:
        reader = DictReader(entities, fieldnames=fieldnames, delimiter=",")
        return list(reader)

    def _convert_ip_to_stix(
        self, ip: str, labels: list[str]
    ) -> tuple[IPv4Address | IPv6Address | None, int | None]:
        """
        Convert IOC's associated IPs to STIX 2.1 IPs Observables and link them to the main Observable.
        :param ip: single ip address
        :param labels: Labels to set to STIX 2.1 IP observable
        :return: observable or none if the ip can't be parsed
        """
        stix_ip_object = None
        ip_version = None
        stix_values = dict(
            value=ip,
            object_marking_refs=[DEFAULT_TLP],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "labels": labels,
            },
        )
        try:
            ip_parsed = ip_address(ip)
            if ip_parsed.version == 4:
                stix_ip_object = IPv4Address(**stix_values)
                ip_version = 4
            elif ip_parsed.version == 6:
                stix_ip_object = IPv6Address(**stix_values)
                ip_version = 6
        except AddressValueError:
            self.helper.log_warning(
                f"Unable to convert IP address, bad format for IP = {ip}"
            )
        return stix_ip_object, ip_version

    @staticmethod
    def _create_relation(source_id: str, target_id: str, relation: str) -> Relationship:
        """
        Create a STIX 2.1 Relationship object.
        :param source_id: STIX 2.1 source object's ID
        :param target_id: STIX 2.1 target object's ID
        :param relation: Name of relationship to create
        :return: STIX 2.1 relationship object
        """
        stix_relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                relation,
                source_id,
                source_id,
            ),
            relationship_type=relation,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[DEFAULT_TLP],
        )
        return stix_relationship

    def convert_collection_to_stix(self, collection: str, entities: list[str]):
        return self.collection_to_stix_function[collection](entities, collection)

    def convert_domain_ioc_to_stix(self, entities: list[str], collection: str):
        domain_schema = ["domain", "tag", "fetch_date", "ref_url"]
        entities_as_dict = self._csv_strings_to_dict(entities, domain_schema)
        stix_objects = []
        for entity in entities_as_dict:
            bundle_objects = []
            cleaned_tag = entity.get("tag").replace("Domain used by ", "")
            # Appears in the tags and is unnecessary
            pattern_value = "[domain-name:value = '" + entity.get("domain") + "']"
            stix_observable = DomainName(
                value=entity.get("domain"),
                object_marking_refs=[DEFAULT_TLP],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": DEFAULT_CONFIDENCE_LEVEL,
                    "labels": [cleaned_tag],
                },
            )
            stix_indicator = self._create_stix_indicator(
                pattern_value=pattern_value,
                name=entity.get("domain"),
                observable_type="Domain",
                labels=[cleaned_tag, collection],
                valid_from=parse(entity.get("fetch_date")),
            )
            # create relation between observable and indicator
            stix_relationship = self._create_relation(
                stix_indicator.id, stix_observable.id, "based-on"
            )

            # add object in the bundle_objects
            bundle_objects.append(stix_indicator)
            bundle_objects.append(stix_observable)
            bundle_objects.append(stix_relationship)
            stix_objects.append(bundle_objects)
        return stix_objects

    def convert_ip_ioc_to_stix(self, entities, collection):
        """
        Convert an ip-based indicator entity from Bambenek into a STIX entity (indicator and related observables)
        """
        ip_schema = ["ip", "tag", "fetch_date", "ref_url"]
        entities_as_dict = self._csv_strings_to_dict(entities, ip_schema)
        stix_objects = []
        for entity in entities_as_dict:
            bundle_objects = []
            # Appears in the tags and is unnecessary
            cleaned_tag = entity.get("tag").replace("IP used by ", "")
            stix_observable, ip_version = self._convert_ip_to_stix(
                ip=entity.get("ip"), labels=[cleaned_tag]
            )
            if not stix_observable:
                continue
            pattern_value = f"[ipv{ip_version}-addr:value = '" + entity.get("ip") + "']"
            observable_type = f"IPv{ip_version}-Addr"
            stix_indicator = self._create_stix_indicator(
                pattern_value=pattern_value,
                name=entity.get("ip"),
                observable_type=observable_type,
                labels=[cleaned_tag, collection],
                valid_from=parse(entity.get("fetch_date")),
            )
            # create relation between observable and indicator
            stix_relationship = self._create_relation(
                stix_indicator.id, stix_observable.id, "based-on"
            )

            # add object in the bundle_objects
            bundle_objects.append(stix_indicator)
            bundle_objects.append(stix_observable)
            bundle_objects.append(stix_relationship)
            stix_objects.append(bundle_objects)
        return stix_objects
