import os
from typing import Dict

import tldextract
import yaml
from pycti import (
    STIX_EXT_OCTI,
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
)
from pymispwarninglists import WarningLists

# At the moment it is not possible to map lists to their upstream path.
# Thus we need to have our own mapping here.
# Reference: https://github.com/MISP/misp-warninglists/issues/142
# To generate: grep '"name"' -r lists, and then reformat using vscode
LIST_MAPPING = {
    "List of known Akamai IP ranges": "lists/akamai/list.json",
    "Top 1000 website from Alexa": "lists/alexa/list.json",
    "List of known Amazon AWS IP address ranges": "lists/amazon-aws/list.json",
    "List of known Apple IP ranges": "lists/apple/list.json",
    "List of known domains used by automated malware analysis services & security vendors": "lists/automated-malware-analysis/list.json",
    "List of known bank domains": "lists/bank-website/list.json",
    "Captive Portal Detection Hostnames": "lists/captive-portals/list.json",
    "Censys IP Ranges Used for Scanning": "lists/censys-scanning/list.json",
    "List of known check-host.net IP address ranges": "lists/check-host-net/list.json",
    "Top 1000 websites from Cisco Umbrella": "lists/cisco_top1000/list.json",
    "Top 10 000 websites from Cisco Umbrella": "lists/cisco_top10k/list.json",
    "Top 20 000 websites from Cisco Umbrella": "lists/cisco_top20k/list.json",
    "Top 5000 websites from Cisco Umbrella": "lists/cisco_top5k/list.json",
    "List of known Cloudflare IP ranges": "lists/cloudflare/list.json",
    "Common contact e-mail addresses": "lists/common-contact-emails/list.json",
    "List of known hashes with common false-positives (based on Florian Roth input list)": "lists/common-ioc-false-positive/list.json",
    "Valid covid-19 related domains": "lists/covid/list.json",
    "Covid-19 Cyber Threat Coalition's Whitelist": "lists/covid-19-cyber-threat-coalition-whitelist/list.json",
    "Covid-19 Krassi's Whitelist": "lists/covid-19-krassi-whitelist/list.json",
    "CRL and OCSP domains": "lists/crl-hostname/list.json",
    "CRL and OCSP IP addresses": "lists/crl-ip/list.json",
    "List of known dax30 webpages": "lists/dax30/list.json",
    "OSINT.DigitalSide.IT Warning List": "lists/digitalside/list.json",
    "List of disposable email domains": "lists/disposable-email/list.json",
    "List of known dynamic DNS domains": "lists/dynamic-dns/list.json",
    "List of hashes for EICAR test virus": "lists/eicar.com/list.json",
    "List of known hashes for empty files": "lists/empty-hashes/list.json",
    "List of known Fastly IP address ranges": "lists/fastly/list.json",
    "List of known hostname used for querying your source IP. This can be used as exclusion for your Passive DNS lookup.": "lists/findip-host/list.json",
    "List of known google domains": "lists/google/list.json",
    "google-chrome-crux-1million": "lists/google-chrome-crux-1million/list.json",
    "List of known GCP (Google Cloud Platform) IP address ranges": "lists/google-gcp/list.json",
    "List of known Gmail sending IP ranges": "lists/google-gmail-sending-ips/list.json",
    "List of known Googlebot IP ranges (https://developers.google.com/search/apis/ipranges/googlebot.json)": "lists/googlebot/list.json",
    "TLDs as known by IANA": "lists/tlds/list.json",
    "List of IPv6 link local blocks": "lists/ipv6-linklocal/list.json",
    "List of known link in Bio domains": "lists/link-in-bio/list.json",
    "Top 10000 websites from Majestic Million": "lists/majestic_million/list.json",
    "List of known microsoft domains": "lists/microsoft/list.json",
    "List of known Office 365 Attack Simulator used for phishing awareness campaigns": "lists/microsoft-attack-simulator/list.json",
    "List of known Microsoft Azure Datacenter IP Ranges": "lists/microsoft-azure/list.json",
    "List of Azure Applicaiton IDs": "lists/microsoft-azure-appid/list.json",
    "List of known Microsoft Azure China Datacenter IP Ranges": "lists/microsoft-azure-china/list.json",
    "List of known Microsoft Azure Germany Datacenter IP Ranges": "lists/microsoft-azure-germany/list.json",
    "List of known Microsoft Azure US Government Cloud Datacenter IP Ranges": "lists/microsoft-azure-us-gov/list.json",
    "List of known Office 365 URLs": "lists/microsoft-office365/list.json",
    "List of known Office 365 IP address ranges in China": "lists/microsoft-office365-cn/list.json",
    "List of known Office 365 IP address ranges": "lists/microsoft-office365-ip/list.json",
    "List of known Windows 10 connection endpoints": "lists/microsoft-win10-connection-endpoints/list.json",
    "Top 500 domains and pages from https://moz.com/top500": "lists/moz-top500/list.json",
    "Fingerprint of trusted CA certificates": "lists/mozilla-CA/list.json",
    "Fingerprint of known intermediate of trusted certificates": "lists/mozilla-IntermediateCA/list.json",
    "List of RFC 5771 multicast CIDR blocks": "lists/multicast/list.json",
    "List of known hashes for benign files": "lists/nioc-filehash/list.json",
    "List of known IP address ranges for OpenAI GPT crawler bot": "lists/openai-gptbot/list.json",
    "List of known Ovh Cluster IP": "lists/ovh-cluster/list.json",
    "Parking domains": "lists/parking-domain/list.json",
    "Parking domains name server": "lists/parking-domain-ns/list.json",
    "Unattributed phone number.": "lists/phone_numbers/list.json",
    "List of known public DNS resolvers expressed as hostname": "lists/public-dns-hostname/list.json",
    "List of known IPv4 public DNS resolvers": "lists/public-dns-v4/list.json",
    "List of known IPv6 public DNS resolvers": "lists/public-dns-v6/list.json",
    "List of known public IPFS gateways": "lists/public-ipfs-gateways/list.json",
    "List of RFC 1918 CIDR blocks": "lists/rfc1918/list.json",
    "List of RFC 3849 CIDR blocks": "lists/rfc3849/list.json",
    "List of RFC 5735 CIDR blocks": "lists/rfc5735/list.json",
    "List of RFC 6598 CIDR blocks": "lists/rfc6598/list.json",
    "List of RFC 6761 Special-Use Domain Names": "lists/rfc6761/list.json",
    "List of known security providers/vendors blog domain": "lists/security-provider-blogpost/list.json",
    "List of known sinkholes": "lists/sinkholes/list.json",
    "List of known SMTP receiving IP addresses": "lists/smtp-receiving-ips/list.json",
    "List of known SMTP sending IP ranges": "lists/smtp-sending-ips/list.json",
    "List of known Stackpath CDN IP ranges": "lists/stackpath/list.json",
    "List of known Tenable Cloud Sensors IPv4": "lists/tenable-cloud-ipv4/list.json",
    "List of known Tenable Cloud Sensors IPv6": "lists/tenable-cloud-ipv6/list.json",
    "Hashes that are often included in IOC lists but are false positives.": "lists/ti-falsepositives/list.json",
    "Top 1000000 most-used sites from Tranco": "lists/tranco/list.json",
    "Top 10K most-used sites from Tranco": "lists/tranco10k/list.json",
    "cisco-umbrella-blockpage-hostname": "lists/umbrella-blockpage-hostname/list.json",
    "cisco-umbrella-blockpage-ipv4": "lists/umbrella-blockpage-v4/list.json",
    "cisco-umbrella-blockpage-ipv6": "lists/umbrella-blockpage-v6/list.json",
    "University domains": "lists/university_domains/list.json",
    "List of known URL Shorteners domains": "lists/url-shortener/list.json",
    "Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters": "lists/vpn-ipv4/list.json",
    "Specialized list of IPv6 addresses belonging to common VPN providers and datacenters": "lists/vpn-ipv6/list.json",
    "List of known domains to know external IP": "lists/whats-my-ip/list.json",
    "List of known Wikimedia address ranges": "lists/wikimedia/list.json",
    "List of known Zscaler IP address ranges": "lists/zscaler/list.json",
}


class HygieneConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)

        warninglists_slow_search = bool(
            get_config_variable(
                "HYGIENE_WARNINGLISTS_SLOW_SEARCH",
                ["hygiene", "warninglists_slow_search"],
                config,
                default=False,
            )
        )

        self.enrich_subdomains = bool(
            get_config_variable(
                "HYGIENE_ENRICH_SUBDOMAINS",
                ["hygiene", "enrich_subdomains"],
                config,
                default=False,
            )
        )

        self.hygiene_label_name = str(
            get_config_variable(
                "HYGIENE_LABEL_NAME",
                ["hygiene", "label_name"],
                config,
                default="hygiene",
            )
        )

        self.hygiene_label_parent_name = str(
            get_config_variable(
                "HYGIENE_LABEL_PARENT_NAME",
                ["hygiene", "label_name"],
                config,
                default="hygiene_parent",
            )
        )

        self.hygiene_label_color = str(
            get_config_variable(
                "HYGIENE_LABEL_COLOR",
                ["hygiene", "label_color"],
                config,
                default="#fc0341",
            )
        )

        self.helper.log_info(f"Warning lists slow search: {warninglists_slow_search}")

        self.warninglists = WarningLists(slow_search=warninglists_slow_search)

        # Create Hygiene Tag
        self.label_hygiene = self.helper.api.label.read_or_create_unchecked(
            value=self.hygiene_label_name, color=self.hygiene_label_color
        )
        if self.label_hygiene is None:
            raise ValueError(
                "The hygiene label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
            )

        if self.enrich_subdomains:
            self.label_hygiene_parent = self.helper.api.label.read_or_create_unchecked(
                value=self.hygiene_label_parent_name, color=self.hygiene_label_color
            )
            if self.label_hygiene_parent is None:
                raise ValueError(
                    "The hygiene label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
                )

    def _process_observable(self, stix_objects, stix_entity, opencti_entity) -> str:
        # Search in warninglist
        result = self.warninglists.search(opencti_entity["observable_value"])

        # If not found and the domain is a subdomain, search with the parent.
        use_parent = False
        if not result and self.enrich_subdomains is True:
            if stix_entity["type"] == "domain-name":
                ext = tldextract.extract(stix_entity["value"])
                if stix_entity["value"] != ext.domain + "." + ext.suffix:
                    result = self.warninglists.search(ext.domain + "." + ext.suffix)
                    use_parent = True

        # Iterate over the hits
        if result:
            self.helper.log_info(
                "Hit found for %s in warninglists"
                % (opencti_entity["observable_value"])
            )

            for hit in result:
                self.helper.log_info(
                    "Type: %s | Name: %s | Version: %s | Descr: %s"
                    % (hit.type, hit.name, hit.version, hit.description)
                )

                # We set the score based on the number of warning list entries
                if len(result) >= 5:
                    score = 5
                elif len(result) >= 3:
                    score = 10
                elif len(result) == 1:
                    score = 15
                else:
                    score = 20

                self.helper.log_info(
                    f"number of hits ({len(result)}) setting score to {score}"
                )

                # Add labels
                if use_parent:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        self.label_hygiene_parent["value"],
                        True,
                    )
                else:
                    OpenCTIStix2.put_attribute_in_extension(
                        stix_entity,
                        STIX_EXT_OCTI_SCO,
                        "labels",
                        self.label_hygiene["value"],
                        True,
                    )

                # Update score
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity, STIX_EXT_OCTI_SCO, "score", score
                )

                # External references
                if hit.name in LIST_MAPPING:
                    url = (
                        "https://github.com/MISP/misp-warninglists/tree/main/"
                        + LIST_MAPPING[hit.name]
                    )
                else:
                    # reference not found in the LIST_MAPPING, define a generic URL
                    url = "https://github.com/MISP/misp-warninglists/tree/main"
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "external_references",
                    {
                        "source_name": "misp-warninglist",
                        "url": url,
                        "external_id": hit.name,
                        "description": hit.description,
                    },
                    True,
                )

                # Add indicators
                for indicator_id in opencti_entity["indicatorsIds"]:
                    stix_indicator = (
                        self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                            entity_type="Indicator",
                            entity_id=indicator_id,
                            only_entity=True,
                        )
                    )

                    # Add labels
                    if use_parent:
                        stix_indicator["labels"] = (
                            (
                                stix_indicator["labels"]
                                + [self.label_hygiene_parent["value"]]
                            )
                            if "labels" in stix_indicator
                            else [self.label_hygiene_parent["value"]]
                        )
                    else:
                        stix_indicator["labels"] = (
                            (stix_indicator["labels"] + [self.label_hygiene["value"]])
                            if "labels" in stix_indicator
                            else [self.label_hygiene["value"]]
                        )

                    # Update score
                    stix_indicator = OpenCTIStix2.put_attribute_in_extension(
                        stix_indicator, STIX_EXT_OCTI, "score", score
                    )

                    # Append
                    stix_objects.append(stix_indicator)

                serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(serialized_bundle)
            return "Observable value found on warninglist and tagged accordingly"

    def _process_message(self, data: Dict) -> str:
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]
        return self._process_observable(stix_objects, stix_entity, opencti_entity)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    HygieneInstance = HygieneConnector()
    HygieneInstance.start()
