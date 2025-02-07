import stix2

from .download_manager import DownloadManager  # Ensure this import is at the top
from .stix_utils import StixUtils  # Import the centralized StixUtils class
from .workflow_processor import WorkflowProcessor  # Import the WorkflowProcessor class


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        helper,
        tlp_marking,
        author_name,
        labels,
        download_payloads=False,
        proxy_url=None,
    ):
        self.helper = helper
        self.tlp_marking = tlp_marking
        self.stix_labels = labels
        self.download_payloads = download_payloads
        self.download_manager = DownloadManager(
            helper, proxy_url=proxy_url
        )  # Instantiate DownloadManager

        # Initialize STIX utilities with helper
        self.stix_utils = StixUtils(
            helper=self.helper,  # Pass the helper
            tlp_marking=self.tlp_marking,
            stix_labels=self.stix_labels,
        )

        # Create the author identity via StixUtils
        self.author_identity = self.stix_utils.create_identity(author_name)

        # Initialize WorkflowProcessor with required arguments
        self.workflow_processor = WorkflowProcessor(
            stix_utils=self.stix_utils,  # Pass the initialized stix_utils
            helper=self.helper,
            download_manager=self.download_manager,
            stix_labels=self.stix_labels,
            tlp_marking=self.tlp_marking,
            create_stix_entity=self.stix_utils.create_stix_entity,
            create_relationship=self.stix_utils.create_relationship,
            fang_indicator=self.stix_utils.fang_indicator,
        )
        self.stix_objects = self.stix_utils.stix_objects

    def export_to_stix(self, df):
        """Export the data from the DataFrame to STIX2 format."""
        file_hash_mapping = {}

        for _, row in df.iterrows():
            src_ip = row.get("src_ip", None)
            attacker_commands = row.get("input", "")
            fanged_attacker_commands = self.stix_utils.fang_indicator(attacker_commands)
            timestamp = row.get("@timestamp", "")
            honeypot_type = row.get("type", "Unknown Honeypot Type")
            ip_rep = row.get("ip_rep", None)

            custom_labels = self.stix_labels + [honeypot_type]
            if ip_rep:
                custom_labels.append(ip_rep)

            fanged_src_ip = (
                self.stix_utils.fang_indicator(src_ip)
                if src_ip
                else "Error while fanging IP."
            )

            # Creating IP observable
            if src_ip and len(attacker_commands) > 2:
                src_ip_object = self.stix_utils.create_stix_entity(
                    "ipv4-addr",
                    description=f"Source IP observable for {self.stix_utils.fang_indicator(src_ip)}",
                    value=src_ip,
                    custom_properties={"x_opencti_labels": self.stix_labels},
                )

                # Create geolocation and relate it to src_ip_object
                geoip_data = row.get("geoip", {})
                if geoip_data:
                    self.stix_utils._generate_stix_location(geoip_data, src_ip_object)

                    if geoip_data.get("asn"):
                        asn_entity = self.stix_utils._generate_stix_asn(geoip_data)

                        self.stix_utils.create_relationship(
                            source_ref=src_ip_object["id"],
                            target_ref=asn_entity["id"],
                            relationship_type="belongs-to",
                            custom_properties={"x_opencti_labels": custom_labels},
                        )

                # Create and add an observable object for sightings
                self.stix_utils.create_stix_entity(
                    "observed-data",
                    description=f"Observed data for source IP {fanged_src_ip}, detected by {honeypot_type}",
                    objects={"0": src_ip_object},
                    first_observed=timestamp,
                    last_observed=timestamp,
                    number_observed=1,
                    created_by_ref=self.author_identity["id"],
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                # Create an indicator for the IP address
                indicator_pattern = f"[ipv4-addr:value = '{src_ip}']"
                indicator_src_ip = self.stix_utils.create_stix_entity(
                    "indicator",
                    description=f"Indicator for malicious IP: {fanged_src_ip}, detected by {honeypot_type}",
                    pattern=indicator_pattern,
                    pattern_type="stix",
                    valid_from=timestamp,
                    indicator_types=["malicious-activity"],
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                # Create a relationship between the IP indicator and the IP object
                self.stix_utils.create_relationship(
                    source_ref=indicator_src_ip["id"],
                    target_ref=src_ip_object["id"],
                    relationship_type="based-on",
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                # Create or find the note
                self.stix_utils.create_or_find_note(
                    fanged_attacker_commands, src_ip_object, indicator_src_ip
                )

                # Fixme ask filigran to create a custom observable that can be imported via pycti to not use api.
                """ 
                # Extract SSH-RSA keys if present
                parsed_data = download_manager.extract_network_indicators(attacker_commands)
                extracted_ssh_keys = parsed_data.get('ssh_keys', [])
                
                if extracted_ssh_keys:
                    for ssh_key in extracted_ssh_keys:
                        self.helper.log_info(f"Extracted SSH key: {ssh_key}")
                        
                        # Create a cryptographic-key STIX object
                        ssh_key_object, is_new_ssh_key = self.stix_utils.create_stix_entity(
                            'Cryptographic-Key',  # Using cryptographic-key as the custom object type
                            description=f"SSH-RSA key detected in attacker command, detected by {honeypot_type}",
                            value=ssh_key,
                            custom_properties={"x_opencti_labels": custom_labels}
                        )
                        if is_new_ssh_key:
                            self.stix_utils.create_stix_entity(ssh_key_object)

                             Create a relationship between the IP and the cryptographic key
                            rel_ip_ssh_key = self.stix_utils.create_relationship(
                                source_ref=src_ip_object,
                                target_ref=ssh_key_object,
                                relationship_type="related-to",
                                custom_properties={"x_opencti_labels": custom_labels}
                            )
                           self.stix_utils.create_stix_entity(rel_ip_ssh_key)
                """
                if self.download_payloads:
                    # Extract C2 URLs using DownloadManager methods from strings commands left by the attacker/bot
                    parsed_data = self.download_manager.extract_network_indicators(
                        attacker_commands
                    )
                    c2_urls = parsed_data.get("urls", [])

                    # Log extracted URLs before processing
                    if c2_urls:
                        self.helper.log_info(f"Extracted C2 URLs: {c2_urls}")

                        # Process the C2 URLs
                        self.workflow_processor.process_workflow(
                            c2_urls,
                            file_hash_mapping,
                            src_ip_object,
                            honeypot_type,
                            parsed_data,
                            max_iterations=5,
                        )
        self.helper.log_info(f"Exported STIX objects count: {len(self.stix_objects)}")
        return self.stix_objects
