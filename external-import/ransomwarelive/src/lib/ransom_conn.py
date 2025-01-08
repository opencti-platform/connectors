import datetime as dt
import os
import sys
import time
from datetime import datetime

import pycti
import requests
import tldextract
import validators
import whois
from pycti import OpenCTIConnectorHelper
from stix2 import (
    TLP_WHITE,
    Bundle,
    DomainName,
    ExternalReference,
    Identity,
    IntrusionSet,
    IPv4Address,
    IPv6Address,
    Location,
    Relationship,
    Report,
    ThreatActor,
)


class RansomwareAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the
        final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.work_id = None
        self.get_historic = os.environ.get("CONNECTOR_PULL_HISTORY", "false").lower()
        self.get_historic_year = os.environ.get(
            "CONNECTOR_HISTORY_START_YEAR", 2020
        ).lower()
        # Specific connector attributes for external import connectors
        try:
            self.interval = os.environ.get("CONNECTOR_RUN_EVERY", None).lower()
            self.helper.log_info(
                f"Verifying integrity of the CONNECTOR_RUN_EVERY value: '{self.interval}'"
            )
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as _:
            msg = (
                f"Error ({_}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. It SHOULD"
                f" be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd',"
                f" 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            )
            self.helper.log_error(msg)
            raise ValueError(msg) from _

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        self.tlp_marking = "TLP:WHITE"
        self.marking = TLP_WHITE
        author = Identity(
            id=pycti.Identity.generate_id("Ransomware.Live", "organization"),
            name="Ransomware.Live",
            identity_class="organization",
            type="identity",
            object_marking_refs=[self.marking.get("id")],
            contact_information="https://www.ransomware.live/#/about?id=⚙️-integration-with-opencti",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )
        self.author = author

        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            self.update_existing_data = update_existing_data.lower() == "true"
        elif isinstance(update_existing_data, bool) and update_existing_data.lower in [
            True,
            False,
        ]:
            self.update_existing_data = update_existing_data
        else:
            msg = (
                f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'."
                f" It SHOULD be either `true` or `false`. `false` is assumed. "
            )
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    # Generates a group description from the ransomware.live API data
    def threat_discription_generater(self, group_name, group_data):

        matching_items = [
            item for item in group_data if item.get("name", None) == group_name
        ]

        if matching_items and matching_items[0].get("description") is not (
            None or "" or " " or "null"
        ):
            description = matching_items[0].get(
                "description", "No description available"
            )

        else:
            description = "No description available"
        return description

    # Generates a relationship object
    def relationship_generator(self, source_ref, target_ref, relationship_type):
        relation = Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type,
                source_ref,
                target_ref,
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author.get("id"),
        )
        return relation

    # Validates if the input is a domain
    def is_domain(self, name):
        return bool(validators.domain(name))

    # Validates if the input is an IPv4 address
    def is_ipv4(self, ip):
        return bool(validators.ipv4(ip))

    # Validates if the input is an IPv6 address
    def is_ipv6(self, ip):
        return bool(validators.ipv6(ip))

    # Fetches the IP address of a domain
    def ip_fetcher(self, domain):

        try:
            params = {"name": domain, "type": "A"}

            headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

            response = requests.get(
                "https://dns.google/resolve",
                headers=headers,
                params=params,
                timeout=(20000, 20000),
            )

            if response.status_code == 200:
                response_json = response.json()
                if response_json.get("Answer") is not None:
                    for item in response_json.get("Answer"):
                        if item.get("type") == 1 and self.is_ipv4(item.get("data")):
                            ip_address = item.get("data")
                            return ip_address
            return None
        except Exception as e:

            self.helper.log_error(f"Error fetching IP address{domain}")
            self.helper.log_error(str(e))
            return None

    # Fetches the whois information of a domain
    def fetch_country_domain(self, domain):
        try:
            w = whois.whois(domain)
        except Exception as e:
            self.helper.log_error(f"Error fetching WHOIS for domain {domain}")
            self.helper.log_error(str(e))
            return None

        try:
            description = f"Domain:{domain}  \n"
            # Using whois data from w instead of response_json
            if w is not None:
                if w.get("country") is not None:
                    description += f" is registered in {w.get('country')}  \n"
                if w.get("registrar") is not None:
                    description += f"registered with {w.get('registrar')}  \n"
                if w.get("creation_date") is not None:
                    description += f" creation_date {w.get('creation_date')}  \n"
                if w.get("expiration_date") is not None:
                    description += f" expiration_date {w.get('expiration_date')}  \n"

        except Exception as e:
            self.helper.log_error(f"Error fetching whois for domain {domain}")
            self.helper.log_error(str(e))
            return None

        return description

    # Extracts the domain from a URL
    def domain_extractor(self, url):
        try:
            if validators.domain(url):
                return url
            domain = tldextract.extract(url).registered_domain
            if validators.domain(domain):
                return domain
            return None
        except Exception as e:
            self.helper.log_error("Error extracting domain")
            self.helper.log_error(str(e))
            return None

    # Fetches the location object from OpenCTI
    def opencti_location_check(self, country):
        country_id = pycti.Location.generate_id(country, "Country")
        try:
            country_out = self.helper.api.stix_domain_object.read(id=country_id)
            if country_out and country_out.get("standard_id").startswith("location--"):
                return country_out.get("standard_id")
            return None
        except Exception as e:
            self.helper.log_error(f"Error fetching location{country}")
            self.helper.log_error(str(e))
            return None

    def sector_fetcher(self, sector):
        try:
            sectors_split = []
            rubbish = [" and ", " or ", " ", ";"]
            for item in rubbish:
                sector = " ".join(sector.split(item))

            sectors_split = sector.split()
            for item in sectors_split:
                if item in ("and", "or", ",", ", "):
                    sectors_split.remove(item)
                else:
                    item2 = item.strip()
                    sectors_split.remove(item)
                    sectors_split.append(item2)

            filtered_sectors = [
                {"key": "entity_type", "values": ["Sector"], "operator": "eq"},
            ]
            for sub_sector in sectors_split:
                sub_filter = {
                    "key": "name",
                    "values": [sub_sector],
                    "mode": "or",
                    "operator": "eq",
                }
                filtered_sectors.append(sub_filter)

            sector_out = self.helper.api.identity.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "entity_type", "values": ["Sector"], "operator": "eq"},
                        {
                            "key": "name",
                            "values": sector,
                            "mode": "or",
                            "operator": "search",
                        },
                    ],
                    "filterGroups": [],
                },
            )
            if sector_out and sector_out.get("standard_id").startswith("identity--"):
                return sector_out.get("standard_id")
            return None

        except Exception as e:
            self.helper.log_error(f"Errot fetching sector{sector}")
            self.helper.log_error(str(e))
            return None

    def ip_object_creator(self, ip):
        try:
            if self.is_ipv4(ip):
                return self.ipv4_generator(ip)
            if self.is_ipv6(ip):
                return self.ipv6_generator(ip)
            return None
        except Exception as e:
            self.helper.log_error(f"Error creating IP object{ip}")
            self.helper.log_error(str(e))
            return None

    # Generates a ransom note external reference

    def ransome_note_generator(self, group_name):

        if group_name in ("lockbit3", "lockbit2"):
            return ExternalReference(
                source_name="Ransom Note",
                url="https://www.ransomware.live/#/notes/lockbit",
                description="Sample Ransom Note",
            )
        return ExternalReference(
            source_name="Ransom Note",
            url=f"https://www.ransomware.live/#/notes/{group_name}",
            description="Sample Ransom Note",
        )

    # Generates a STIX object for an IPv4 address
    def ipv4_generator(self, ip):
        return IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    # Generates a STIX object for an IPv6 address
    def ipv6_generator(self, ip):
        return IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    # Generates a STIX object for a domain
    def domain_generator(self, domain_name, description="-"):
        domain = DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            allow_custom=True,
            created_by_ref=self.author.get("id"),
            x_opencti_description=description,
        )
        return domain

    # Generates STIX objects from the ransomware.live API data
    # pylint:disable=too-many-branches,too-many-statements
    def stix_object_generator(self, item, group_data):
        """Generates STIX objects from the ransomware.live API data"""

        # Creating Victim object
        post_title = item.get("post_title")
        victim_name, identity_class = (
            (post_title, "organization")
            if len(post_title) > 2
            else ((post_title + ":<)"), "individual")
        )
        victim = Identity(
            id=pycti.Identity.generate_id(victim_name, identity_class),
            name=victim_name,
            identity_class=identity_class,
            type="identity",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )

        # RansomNote External Reference
        external_references_group = self.ransome_note_generator(item.get("group_name"))

        # Creating Threat Actor object
        threat_actor_name = item.get("group_name")
        threat_actor = ThreatActor(
            id=pycti.ThreatActorGroup.generate_id(threat_actor_name),
            name=threat_actor_name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=self.threat_discription_generater(
                item.get("group_name"), group_data
            ),
            object_marking_refs=[self.marking.get("id")],
            external_references=[external_references_group],
        )

        target_relation = self.relationship_generator(
            threat_actor.get("id"), victim.get("id"), "targets"
        )

        # Creating Intrusion Set object
        try:
            if (
                item.get("group_name") == "lockbit3"
                or item.get("group_name") == "lockbit2"
            ):

                intrusionset = IntrusionSet(
                    id=pycti.IntrusionSet.generate_id("lockbit"),
                    name="lockbit",
                    labels=["ransomware"],
                    created_by_ref=self.author.get("id"),
                    description=self.threat_discription_generater(
                        item.get("lockbit3"), group_data
                    ),
                    object_marking_refs=[self.marking.get("id")],
                    external_references=[external_references_group],
                )

            else:
                intrusionset_name = item.get("group_name")
                intrusionset = IntrusionSet(
                    id=pycti.IntrusionSet.generate_id(intrusionset_name),
                    name=intrusionset_name,
                    labels=["ransomware"],
                    created_by_ref=self.author.get("id"),
                    description=self.threat_discription_generater(
                        item.get("group_name"), group_data
                    ),
                    object_marking_refs=[self.marking.get("id")],
                    external_references=[external_references_group],
                )

            relation_vi_is = self.relationship_generator(
                intrusionset.get("id"), victim.get("id"), "targets"
            )
            relation_is_ta = self.relationship_generator(
                intrusionset.get("id"), threat_actor.get("id"), "attributed-to"
            )

        except Exception as e:
            self.helper.log_error(str(e))

        # Creating External References Object if they have external references
        external_references = [external_references_group]

        for field in ["screenshot", "website", "post_url"]:

            if item.get(field):
                external_reference = ExternalReference(
                    source_name="ransomware.live",
                    url=item[field],
                    description=f"This is the {field} for the ransomware campaign.",
                )
                external_references.append(external_reference)

        # Creating Report object
        report_name = (
            item.get("group_name") + " has published a new victim: " + post_title
        )
        report_created = datetime.fromisoformat(item.get("discovered"))
        report_published = datetime.fromisoformat(item.get("published"))
        report = Report(
            id=pycti.Report.generate_id(report_name, report_published),
            report_types=["Ransomware-report"],
            name=report_name,
            description=item.get("description"),
            created_by_ref=self.author.get("id"),
            object_refs=[
                threat_actor.get("id"),
                victim.get("id"),
                intrusionset.get("id"),
                target_relation.get("id"),
                relation_vi_is.get("id"),
                relation_is_ta.get("id"),
            ],
            published=report_published,
            created=report_created,
            object_marking_refs=[self.marking.get("id")],
            external_references=external_references,
        )

        # Initial Bundle objects
        bundle = [
            self.author,
            victim,
            threat_actor,
            intrusionset,
            target_relation,
            relation_is_ta,
            relation_vi_is,
        ]

        # Creating Sector object

        try:

            if item.get("activity") is not None:

                sector_id = self.sector_fetcher(item.get("activity"))
                if sector_id is not None:
                    relation_sec_vic = self.relationship_generator(
                        victim.get("id"), sector_id, "part-of"
                    )
                    relation_sec_ta = self.relationship_generator(
                        threat_actor.get("id"), sector_id, "targets"
                    )
                    relation_is_sec = self.relationship_generator(
                        intrusionset.get("id"), sector_id, "targets"
                    )
                    bundle.append(relation_sec_vic)
                    bundle.append(relation_sec_ta)
                    bundle.append(relation_is_sec)

                    report.get("object_refs").append(sector_id)
                    report.get("object_refs").append(relation_sec_vic.get("id"))
                    report.get("object_refs").append(relation_sec_ta.get("id"))
                    report.get("object_refs").append(relation_is_sec.get("id"))

        except Exception as e:
            self.helper.log_error(str(e))

        # Creating Domain object
        if self.is_domain(item.get("post_title")):

            domain_name = item.get("post_title")
            # Extracting domain name
            domain_name = self.domain_extractor(domain_name)
            # Fetching domain description
            description = self.fetch_country_domain(domain_name)

            domain = self.domain_generator(item.get("post_title"), description)
            relation_vi_do = self.relationship_generator(
                domain.get("id"), victim.get("id"), "belongs-to"
            )

            # Fetching IP address of the domain
            resolved_ip = self.ip_fetcher(domain_name)

            ip_object = self.ip_object_creator(resolved_ip)

            if ip_object is not None and ip_object.get("id") is not None:
                relation_do_ip = self.relationship_generator(
                    domain.get("id"), ip_object.get("id"), "resolves-to"
                )
                bundle.append(ip_object)
                bundle.append(relation_do_ip)
                report.get("object_refs").append(ip_object.get("id"))
                report.get("object_refs").append(relation_do_ip.get("id"))

            # self.helper.api.stix_cyber_observable.ask_for_enrichment(domain.get("id"))
            report.get("object_refs").append(domain.get("id"))
            report.get("object_refs").append(relation_vi_do.get("id"))
            bundle.append(domain)
            bundle.append(relation_vi_do)

        elif (
            item.get("website") != ""
            and not self.is_domain(item.get("post_title"))
            and item.get("website") is not None
        ):

            if self.domain_extractor(item.get("website")) is not None:

                domain_name = self.domain_extractor(item.get("website"))

                description = self.fetch_country_domain(domain_name)
                try:
                    domain2 = self.domain_generator(domain_name, description)
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating domain object: {domain_name} {description}"
                    )
                    self.helper.log_error(str(e))

                relation_vi_do2 = self.relationship_generator(
                    domain2.get("id"), victim.get("id"), "belongs-to"
                )
                resolved_ip = self.ip_fetcher(domain_name)

                ip_object = self.ip_object_creator(resolved_ip)

                if ip_object is not None:
                    relation_do_ip2 = self.relationship_generator(
                        domain2.get("id"), ip_object.get("id"), "resolves-to"
                    )
                    bundle.append(ip_object)
                    bundle.append(relation_do_ip2)
                    report.get("object_refs").append(ip_object.get("id"))
                    report.get("object_refs").append(relation_do_ip2.get("id"))

                report.get("object_refs").append(domain2.get("id"))
                report.get("object_refs").append(relation_vi_do2.get("id"))
                bundle.append(domain2)
                bundle.append(relation_vi_do2)

        # Creating Location object
        if (
            item.get("country") != ""
            and item.get("country") is not None
            and len(item.get("country", "Four")) < 4
        ):

            country_name = item.get("country")
            country_stix_id = self.opencti_location_check(country_name)
            location3 = Location(
                id=country_stix_id
                or pycti.Location.generate_id(country_name, "Country"),
                name=country_name,
                country=item.get("country"),
                type="location",
                created_by_ref=self.author.get("id"),
                object_marking_refs=[self.marking.get("id")],
            )
            # If country not yet available, add it in the bundle for creation
            if country_stix_id is None:
                bundle.append(location3)

            location_relation = self.relationship_generator(
                victim.get("id"), location3.get("id"), "located-at"
            )

            relation_is_lo = self.relationship_generator(
                intrusionset.get("id"), location3.get("id"), "targets"
            )

            relation_ta_lo = self.relationship_generator(
                threat_actor.get("id"), location3.get("id"), "targets"
            )

            bundle.append(relation_is_lo)
            bundle.append(location_relation)
            bundle.append(relation_ta_lo)

            report.get("object_refs").append(location3.get("id"))
            report.get("object_refs").append(relation_is_lo.get("id"))
            report.get("object_refs").append(relation_ta_lo.get("id"))
            report.get("object_refs").append(location_relation.get("id"))

        bundle.append(report)
        self.helper.log_info(
            f"Sending {len(bundle)} STIX objects to collect_intellegince."
        )
        return bundle

    # Collects historic intelligence from ransomware.live
    def collect_historic_intelligence(self):
        """Collects historic intelligence from ransomware.live"""
        base_url = "https://api.ransomware.live/victims/"
        groups_url = "https://api.ransomware.live/groups"
        headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

        # fetching group information
        try:
            response = requests.get(groups_url, headers=headers, timeout=(20000, 20000))
            group_data = response.json()
        except Exception as e:
            self.helper.log_error(str(e))
            group_data = []

        curent_year = int(dt.date.today().year)
        # Checking if the historic year is less than 2020 as there is no data past 2020
        if int(self.get_historic_year) < 2020:
            year = 2020
        else:
            year = int(self.get_historic_year)

        stix_objects = []
        bundle = []

        for year in range(year, curent_year + 1):  # Looping through the years
            year_url = base_url + str(year)
            for month in range(1, 13):  # Looping through the months
                url = year_url + "/" + str(month)
                response = requests.get(url, headers=headers, timeout=(20000, 20000))

                try:
                    if response.status_code == 200:
                        response_json = response.json()

                        for item in response_json:

                            try:
                                bundle_list = self.stix_object_generator(
                                    item, group_data
                                )
                            except Exception as e:
                                self.helper.log_error(
                                    f"Error creating STIX objects: {item.get('post_title')}"
                                )
                                self.helper.log_error(str(e))

                            if bundle_list is None:
                                self.helper.log_info("No new data to process")

                            else:

                                # Deduplicate the objects
                                bundle_list = self.helper.stix2_deduplicate_objects(
                                    bundle_list
                                )

                                bundle = Bundle(
                                    objects=bundle_list, allow_custom=True
                                ).serialize()

                            if bundle is not None:
                                self.helper.send_stix2_bundle(
                                    bundle,
                                    update=self.update_existing_data,
                                    work_id=self.work_id,
                                )

                            self.helper.log_info(
                                f"Sending {len(bundle_list)} STIX objects to OpenCTI..."
                            )
                    else:

                        self.helper.log_info(
                            f"Error and response status code {response.status_code}"
                        )

                except Exception as e:
                    self.helper.log_error(str(e))
                    return stix_objects

        return None

    def collect_intelligence(self, last_run) -> list:

        url = "https://api.ransomware.live/recentvictims"
        groups_url = "https://api.ransomware.live/groups"
        headers = {"accept": "application/json"}

        # fetching group information
        try:
            response = requests.get(groups_url, headers=headers, timeout=(20000, 20000))
            group_data = response.json()
        except Exception as e:
            self.helper.log_error(str(e))
            group_data = []

        # fetching recent requests
        try:
            response = requests.get(url, headers=headers, timeout=(20000, 20000))
            if response.status_code == 200:
                response_json = response.json()
                stix_objects = []
                for item in response_json:
                    created = datetime.strptime(
                        item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
                    )
                    if last_run is None:
                        time_diff = 1
                    else:
                        time_diff = int(datetime.timestamp(created)) - (
                            int(last_run) - 84600
                        )  # pushing all the data from the last 24 hours
                    if time_diff > 0:
                        bundle_list = self.stix_object_generator(
                            item, group_data
                        )  # calling the stix_object_generator method to create stix objects

                        stix_objects.extend(bundle_list)
                        bundle = None
                        if bundle_list is None:
                            self.helper.log_info("No new data to process")

                        else:

                            # Deduplicate the objects
                            bundle_list = self.helper.stix2_deduplicate_objects(
                                bundle_list
                            )

                            self.helper.log_info(
                                f"Sending {len(bundle_list)} STIX objects to OpenCTI..."
                            )

                            # Creating Bundle
                            bundle = Bundle(
                                objects=bundle_list, allow_custom=True
                            ).serialize()

                        if bundle is not None:
                            self.helper.send_stix2_bundle(
                                bundle,
                                update=self.update_existing_data,
                                work_id=self.work_id,
                            )
                self.helper.log_info(
                    f"Sending {len(stix_objects)} STIX objects to OpenCTI..."
                )
        except Exception as e:
            self.helper.log_error(str(e))
        return []

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD return always the interval in seconds. If the connector is expecting that the parameter is
        received as hoursUncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            if unit == "h":
                # In hours:
                return int(value) * 60 * 60
            if unit == "m":
                # In minutes:
                return int(value) * 60
            if unit == "s":
                # In seconds:
                return int(value)
            raise ValueError(f"Unsupported unit: {unit}")
        except Exception as e:
            self.helper.log_error(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            ) from e

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()

                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    self.work_id = work_id
                    # testing get_historic or pull history config variable

                    try:  # Performing the collection of intelligence

                        if (last_run is None) and (self.get_historic.upper() == "TRUE"):
                            bundle_objects = self.collect_historic_intelligence()
                        else:
                            bundle_objects = self.collect_intelligence(last_run)

                        if bundle_objects is None:
                            self.helper.log_info("No new data to process")
                            bundle = Bundle(
                                objects=bundle_objects, allow_custom=True
                            ).serialize()

                        else:

                            # Deduplicate the objects
                            bundle_objects = self.helper.stix2_deduplicate_objects(
                                bundle_objects
                            )

                            self.helper.log_info(
                                f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                            )

                            # Creating Bundle
                            bundle = Bundle(
                                objects=bundle_objects, allow_custom=True
                            ).serialize()

                        # self.helper.log_info(f"Sending {bundle_objects} STIX objects to OpenCTI...")

                    except Exception as e:
                        self.helper.log_error(str(e))
                        self.helper.log_error("Something Wrong with Bundle creation")

                    try:
                        if bundle_objects is not None:
                            self.helper.send_stix2_bundle(
                                bundle,
                                update=self.update_existing_data,
                                work_id=work_id,
                            )

                    except Exception as e:

                        self.helper.log_error(str(e))
                        self.helper.log_error("Error sending STIX2 bundle to OpenCTI")

                    # Store the current timestamp as a last run
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.log_info(message)

                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = timestamp
                    else:
                        current_state = {"last_run": timestamp}
                    self.helper.set_state(current_state)

                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self._get_interval() / 60 / 60, 2))
                        + " hours"
                    )
                else:
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60, 2))
                        + " hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)
