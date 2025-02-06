import datetime as dt
import os
import sys
import time
from datetime import datetime

import requests
import tldextract
import validators
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


class FalconfeedsAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

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
            msg = f"Error ({_}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            self.helper.log_error(msg)
            raise ValueError(msg)

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        self.tlp_marking = "TLP:WHITE"
        self.marking = TLP_WHITE
        author = Identity(
            name="Falconfeeds",
            identity_class="organization",
            type="identity",
            object_marking_refs=[self.marking.get("id")],
            contact_information="https://falconfeeds.io/",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )
        self.author = author

        self.falconfeeds_api_key = os.environ.get("FALCONFEEDS_API_KEY", None)

        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            self.update_existing_data = (
                True if update_existing_data.lower() == "true" else False
            )
        elif isinstance(update_existing_data, bool) and update_existing_data.lower in [
            True,
            False,
        ]:
            self.update_existing_data = update_existing_data
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    # Generates a group description from the ransomware.live API data
    def threat_discription_generater(self, group_name, group_data):
        if group_data is None:
            return "No description available"

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
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author.get("id"),
        )
        return relation

    # Validates if the input is a domain
    def is_domain(self, name):

        if validators.domain(name):
            return True
        else:
            return False

    # Validates if the input is an IPv4 address
    def is_ipv4(self, ip):
        if validators.ipv4(ip):
            return True
        else:
            return False

    # Validates if the input is an IPv6 address
    def is_ipv6(self, ip):
        if validators.ipv6(ip):
            return True
        else:
            return False

    # Fetches the IP address of a domain
    def ip_fetcher(self, domain):

        try:
            params = {"name": domain, "type": "A"}

            headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

            response = requests.get(
                "https://dns.google/resolve", headers=headers, params=params
            )

            if response.status_code == 200:
                response_json = response.json()
                if response_json.get("Answer") is not None:
                    for item in response_json.get("Answer"):

                        if item.get("type") == 1 and self.is_ipv4(item.get("data")):
                            ip_address = item.get("data")
                            return ip_address
                        else:
                            return None

            else:
                return None
        except Exception as e:

            self.helper.log_error(f"Error fetching IP address{domain}")
            self.helper.log_error(str(e))
            return None

    # Fetches the whois information of a domain
    def fetch_country_domain(self, domain):
        url = f"https://who-dat.as93.net/{domain}"
        headers = {"user-agent": "OpenCTI"}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                response_json = response.json()
                if response_json.get("whoisparser") == "domain is not found":
                    self.helper.log_info(f"Domain {domain} is not found")
                    return None

            else:
                return None
        except Exception as e:
            self.helper.log_error(f"Error fetching WHOIS for domain {domain}")
            self.helper.log_error(str(e))
            return None
        try:
            description = f"Domain:{domain}  \n"
            if (
                response_json.get("domain") is not None
                and response_json.get("administrative") is not None
            ):
                if response_json.get("administrative").get("country") is not None:
                    description += f" is registered in {response_json.get('administrative').get('country')}  \n"
            if response_json.get("registrar") is not None:
                description += (
                    f"registered with {response_json.get('registrar').get('name')}  \n"
                )
            if response_json.get("domain").get("created_date") is not None:
                description += f" creation_date {response_json.get('domain').get('created_date')}  \n"
            if response_json.get("domain").get("expiration_date") is not None:
                description += f" expiration_date {response_json.get('domain').get('expiration_date')}  \n"

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
            else:
                domain = tldextract.extract(url).registered_domain
                if validators.domain(domain):
                    return domain
                else:
                    return None
        except Exception as e:
            self.helper.log_error("Error extracting domain")
            self.helper.log_error(str(e))
            return None

    # Fetches the location object from OpenCTI
    def opencti_location_check(self, country):

        try:
            country_out = self.helper.api.stix_domain_object.read(
                type=["location"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [country]}],
                    "filterGroups": [],
                },
            )
            if country_out and country_out.get("standard_id").startswith("location--"):
                return country_out.get("standard_id")
            else:
                return None
        except Exception as e:
            self.helper.log_error(f"Errot fetching location{country}")
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
                if item == "and" or item == "or" or item == "," or item == ", ":
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
            else:
                return None

        except Exception as e:
            self.helper.log_error(f"Errot fetching sector{sector}")
            self.helper.log_error(str(e))
            return None

    def ip_object_creator(self, ip):
        try:
            if self.is_ipv4(ip):
                Ipv4 = self.ipv4_generator(ip)
                return Ipv4
            elif self.is_ipv6(ip):
                Ipv6 = self.ipv6_generator(ip)
                return Ipv6
            else:
                return None
        except Exception as e:
            self.helper.log_error(f"Error creating IP object{ip}")
            self.helper.log_error(str(e))
            return None

    # Generates a ransom note external reference

    def ransome_note_generator(self, group_name):

        if group_name == "lockbit3" or group_name == "lockbit2":
            return ExternalReference(
                source_name="Ransom Note",
                url="https://www.ransomware.live/#/notes/lockbit",
                description="Sample Ransom Note",
            )
        else:
            return ExternalReference(
                source_name="Ransom Note",
                url=f"https://www.ransomware.live/#/notes/{group_name}",
                description="Sample Ransom Note",
            )

    # Generates a STIX object for an IPv4 address
    def ipv4_generator(self, ip):
        Ipv4 = IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )
        return Ipv4

    # Generates a STIX object for an IPv6 address
    def ipv6_generator(self, ip):
        Ipv6 = IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )
        return Ipv6

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
    def stix_object_generator(self, item, group_data):
        """Generates STIX objects from the ransomware.live API data"""

        bundle = []
        resolved_ip = None
        # Creating Victim object
        victim_org = ""
        victim_industry = ""
        victim_country = ""
        victim_site = ""
        for i in item['victims']:
            if i['type'] == "Organization":
                victim_org = i['value'][0]
            elif i['type'] == "Country":
                victim_country = i['value'][0]
            elif i['type'] == "Industry":
                victim_industry = i['value'][0]
            elif i['type'] == "Site":
                victim_site = i['value'][0]
        
        victim = Identity(
            name=victim_org,
            identity_class="organization",
            type="identity",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )

        # Creating Threat Actor object
        threat_actor = ThreatActor(
            name=item['threatActors'][0]['name'],
            labels=[item['category'].lower()],
            created_by_ref=self.author.get("id"),
            description=item['threatActors'][0]['description'],
            object_marking_refs=[self.marking.get("id")],
        )

        Target_relation = self.relationship_generator(
            threat_actor.get("id"), victim.get("id"), "targets"
        )

        # Creating Intrusion Set object
        try:
        
            intrusionset = IntrusionSet(
                name=item['threatActors'][0]['name'],
                labels=[item['category'].lower()],
                created_by_ref=self.author.get("id"),
                description=item['threatActors'][0]['description'],
                object_marking_refs=[self.marking.get("id")],
            )

            relation_VI_IS = self.relationship_generator(
                intrusionset.get("id"), victim.get("id"), "targets"
            )
            relation_IS_TA = self.relationship_generator(
                intrusionset.get("id"), threat_actor.get("id"), "attributed-to"
            )

        except Exception as e:
            self.helper.log_error(str(e))

        # Creating External References Object if they have external referncees
        external_references = []
        if 'published' in item and 'url' in item['published']:
            external_reference = ExternalReference(
                source_name="Falconfeeds",
                url=item['published']['url'],
                description=f"This is the url for the {item['category'].lower()}.",
            )
            external_references.append(external_reference)
        if victim_site != "":
            external_reference = ExternalReference(
                source_name="Falconfeeds",
                url=victim_site,
                description=f"This is the victim's url.",
            )
            external_references.append(external_reference)


        # Creating Report object
        report = Report(
            report_types=["Falcon-report"],
            name=item['threatActors'][0]['name'] + " has published a new victim: " + victim_org,
            description=item['threatActors'][0]['description'],
            created_by_ref=self.author.get("id"),
            object_refs=[
                threat_actor.get("id"),
                victim.get("id"),
                intrusionset.get("id"),
                Target_relation.get("id"),
                relation_VI_IS.get("id"),
                relation_IS_TA.get("id"),
            ],
            published=datetime.utcfromtimestamp(item["published"]["timestamp"]),
            created=datetime.utcfromtimestamp(item["published"]["timestamp"]),
            object_marking_refs=[self.marking.get("id")],
            external_references=external_references,
        )

        # Initial Bundle objects
        bundle = [
            self.author,
            victim,
            threat_actor,
            intrusionset,
            Target_relation,
            relation_IS_TA,
            relation_VI_IS,
        ]

        # Creating Sector object
        try:
            if victim_industry != "":

                sector_id = self.sector_fetcher(victim_industry)
                if sector_id is not None:
                    relation_sec_vic = self.relationship_generator(
                        victim.get("id"), sector_id, "part-of"
                    )
                    relation_sec_TA = self.relationship_generator(
                        threat_actor.get("id"), sector_id, "targets"
                    )
                    relation_is_sec = self.relationship_generator(
                        intrusionset.get("id"), sector_id, "targets"
                    )
                    bundle.append(relation_sec_vic)
                    bundle.append(relation_sec_TA)
                    bundle.append(relation_is_sec)

                    report.get("object_refs").append(sector_id)
                    report.get("object_refs").append(relation_sec_vic.get("id"))
                    report.get("object_refs").append(relation_sec_TA.get("id"))
                    report.get("object_refs").append(relation_is_sec.get("id"))

        except Exception as e:
            self.helper.log_error(str(e))

        # Creating Domain object
        if self.is_domain(victim_org):

            domain_name = victim_org
            # Extracting domain name
            domain_name = self.domain_extractor(domain_name)
            # Fetching domain description
            description = self.fetch_country_domain(domain_name)

            domain = self.domain_generator(victim_org, description)
            relation_VI_DO = self.relationship_generator(
                domain.get("id"), victim.get("id"), "belongs-to"
            )

            # Fetching IP address of the domain
            resolved_ip = self.ip_fetcher(domain_name)

            ip_object = self.ip_object_creator(resolved_ip)

            if ip_object is not None and ip_object.get("id") is not None:
                relation_DO_IP = self.relationship_generator(
                    domain.get("id"), ip_object.get("id"), "resolves-to"
                )
                bundle.append(ip_object)
                bundle.append(relation_DO_IP)
                report.get("object_refs").append(ip_object.get("id"))
                report.get("object_refs").append(relation_DO_IP.get("id"))

            # self.helper.api.stix_cyber_observable.ask_for_enrichment(domain.get("id"))
            report.get("object_refs").append(domain.get("id"))
            report.get("object_refs").append(relation_VI_DO.get("id"))
            bundle.append(domain)
            bundle.append(relation_VI_DO)

        elif (
            victim_site != ""
            and not self.is_domain(victim_org)
            and victim_site is not None
        ):

            if self.domain_extractor(victim_site) is not None:

                domain_name = self.domain_extractor(victim_site)

                description = self.fetch_country_domain(domain_name)
                try:
                    domain2 = self.domain_generator(domain_name, description)
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating domain object: {domain_name} {description}"
                    )
                    self.helper.log_error(str(e))

                relation_VI_DO2 = self.relationship_generator(
                    domain2.get("id"), victim.get("id"), "belongs-to"
                )
                resolved_ip = self.ip_fetcher(domain_name)

                ip_object = self.ip_object_creator(resolved_ip)

                if ip_object is not None:
                    relation_DO_IP2 = self.relationship_generator(
                        domain2.get("id"), ip_object.get("id"), "resolves-to"
                    )
                    bundle.append(ip_object)
                    bundle.append(relation_DO_IP2)
                    report.get("object_refs").append(ip_object.get("id"))
                    report.get("object_refs").append(relation_DO_IP2.get("id"))

                report.get("object_refs").append(domain2.get("id"))
                report.get("object_refs").append(relation_VI_DO2.get("id"))
                bundle.append(domain2)
                bundle.append(relation_VI_DO2)

        # Creating Location object
        if (
            victim_country != ""
            and victim_country is not None
        ):

            country_stix_id = self.opencti_location_check(victim_country)

            if country_stix_id is not None:
                location3 = Location(
                    id=country_stix_id,
                    name=victim_country,
                    country=victim_country,
                    type="location",
                    created_by_ref=self.author.get("id"),
                    object_marking_refs=[self.marking.get("id")],
                )

            else:
                location3 = Location(
                    name=victim_country,
                    country=victim_country,
                    type="location",
                    created_by_ref=self.author.get("id"),
                    object_marking_refs=[self.marking.get("id")],
                )
                bundle.append(location3)

            Location_relation = self.relationship_generator(
                victim.get("id"), location3.get("id"), "located-at"
            )

            relation_IS_LO = self.relationship_generator(
                intrusionset.get("id"), location3.get("id"), "targets"
            )

            relation_TA_LO = self.relationship_generator(
                threat_actor.get("id"), location3.get("id"), "targets"
            )

            bundle.append(relation_IS_LO)
            bundle.append(Location_relation)
            bundle.append(relation_TA_LO)

            report.get("object_refs").append(location3.get("id"))
            report.get("object_refs").append(relation_IS_LO.get("id"))
            report.get("object_refs").append(relation_TA_LO.get("id"))
            report.get("object_refs").append(Location_relation.get("id"))

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
            response = requests.get(groups_url, headers=headers)
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
                response = requests.get(url, headers=headers)

                try:
                    if response.status_code == 200:
                        response_json = response.json()
                        print(response.raise_for_status())

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

        url = "https://api.falconfeeds.io/merlin/threat/feed"
        headers = {
            "Authorization"     : f"Bearer {self.falconfeeds_api_key}",
            "Accept"            : "application/json"
        }
        items = []

        # fetching recent requests
        try:
            threats = []
            _next = None
            loop = True
            params = {"next" : _next}
            while loop:
                resp = requests.get(url, headers=headers, params=params)
                loop = (resp.status_code == 200)
                result = resp.json()
                items.extend(result['data'])
                if 'next' in result:
                    params['next'] = result['next']
                last_item_timestamp = threats[-1]['timestamp']
                if (last_item_timestamp < last_run) or ('next' not in result):
                    loop = False
        except Exception as e:
            self.helper.log_error(str(e))

        stix_objects = []

        try:
            for item in items:

                created = datetime.utcfromtimestamp(
                    item["published"]["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'
                )

                if last_run is None:
                    time_diff = 1
                else:
                    time_diff = int(datetime.timestamp(created)) - (
                        int(last_run) - 84600
                    )  # pushing all the data from the last 24 hours
                if time_diff > 0:

                    bundle_list = self.stix_object_generator(
                        item, None
                    )  # calling the stix_object_generator method to create stix objects

                    stix_objects.extend(bundle_list)

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
            return None

        
        return None

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD return always the interval in seconds. If the connector is execting that the parameter is received as hoursUncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            elif unit == "h":
                # In hours:
                return int(value) * 60 * 60
            elif unit == "m":
                # In minutes:
                return int(value) * 60
            elif unit == "s":
                # In seconds:
                return int(value)
        except Exception as e:
            self.helper.log_error(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            )

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                self.get_historic = os.environ.get(
                    "CONNECTOR_PULL_HISTORY", "false"
                ).lower()
                self.get_historic_year = os.environ.get(
                    "CONNECTOR_HISTORY_START_YEAR", 2020
                ).lower()

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

                        # if (last_run is None) and (self.get_historic.upper() == "TRUE"):
                        #     bundle_objects = self.collect_historic_intelligence()     # NOT IMPLEMENTED due to falconfeed API limit
                        # else:
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
