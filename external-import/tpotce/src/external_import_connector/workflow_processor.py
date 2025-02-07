import logging
from datetime import datetime
from urllib.parse import urlparse


class WorkflowProcessor:
    def __init__(
        self,
        helper,
        stix_utils,
        download_manager,
        stix_labels,
        tlp_marking,
        create_stix_entity,
        create_relationship,
        fang_indicator,
    ):
        self.helper = helper
        self.stix_utils = stix_utils  # Assign stix_utils as an instance attribute
        self.download_manager = download_manager
        self.stix_labels = stix_labels
        self.tlp_marking = tlp_marking
        self.fang_indicator = fang_indicator

    def extract_ip_from_url(self, url):
        """Extract the IP address from a URL."""
        parsed_url = urlparse(url)
        return (
            parsed_url.hostname
            if parsed_url.hostname and parsed_url.hostname.replace(".", "").isdigit()
            else None
        )

    def process_workflow(
        self,
        urls,
        file_hash_mapping,
        src_ip_object,
        honeypot_type,
        parsed_data,
        max_iterations=5,
    ):
        processed_urls = set()
        current_urls = urls
        iteration = 0

        if not current_urls:
            self.helper.log_info("No URLs provided for processing.")
            return [], []

        custom_labels = self.stix_labels + [honeypot_type]

        while current_urls and iteration < max_iterations:
            new_urls = []
            iteration += 1
            self.helper.log_info(
                f"Iteration {iteration} of process_workflow with {len(current_urls)} URLs to process."
            )

            for url in current_urls:
                if url in processed_urls:
                    self.helper.log_info(f"URL {url} has already been processed.")
                    continue

                self.helper.log_info(f"Processing URL: {url}")
                (
                    sha256,
                    sha1,
                    md5,
                    sha512,
                    file_size,
                    mime_type,
                    file_name,
                    parsed_data,
                    file_path,
                ) = self.download_manager.download_and_extract_file_info(url)

                if not sha256 and not sha1 and not md5:
                    logging.warning(f"No valid file downloaded or hashed from {url}.")
                    continue

                if not file_path:
                    logging.warning(f"File not found for URL: {url}.")
                    continue

                # Fang the URL for use in descriptions
                fanged_url = self.fang_indicator(url)

                # Create and add the URL object
                description = (
                    f"Observable URL for {fanged_url}, detected by {honeypot_type}"
                )
                url_object = self.stix_utils.create_stix_entity(
                    "url",
                    value=url,
                    description=description,
                    custom_properties={
                        "x_opencti_type": "URL",
                        "x_opencti_labels": custom_labels,
                    },
                    object_marking_refs=[self.tlp_marking.id],
                )

                # Create an indicator for the URL
                indicator_description = (
                    f"Indicator for URL {fanged_url}, detected by {honeypot_type}"
                )
                url_indicator = self.stix_utils.create_stix_entity(
                    "indicator",
                    name=f"Indicator for URL {fanged_url}",
                    pattern_type="stix",
                    pattern=f"[url:value = '{url}']",
                    description=indicator_description,
                    valid_from=datetime.utcnow(),
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                if url_indicator:

                    # Create a relationship between the URL indicator and the URL object
                    self.stix_utils.create_relationship(
                        source_ref=url_indicator,
                        target_ref=url_object,
                        relationship_type="based-on",
                        custom_properties={"x_opencti_labels": custom_labels},
                    )

                # Create a relationship between the URL and the IP address (Parent IP)
                self.stix_utils.create_relationship(
                    source_ref=url_object,
                    target_ref=src_ip_object,
                    relationship_type="related-to",
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                # Extract IP address from the URL and create IP observables and indicators
                parsed_ip = self.extract_ip_from_url(url)

                if parsed_ip:
                    self.helper.log_info(
                        f"Extracted IP address from the URL parsed: {url}"
                    )

                    fanged_ip = self.fang_indicator(parsed_ip)

                    # Create an observable for the IP address
                    ip_description = f"IP {fanged_ip} extracted from C2 URL {fanged_url}, detected by {honeypot_type}"
                    ip_object = self.stix_utils.create_stix_entity(
                        "ipv4-addr",
                        value=parsed_ip,
                        description=ip_description,
                        custom_properties={
                            "x_opencti_type": "IPv4-Addr",
                            "x_opencti_labels": custom_labels,
                        },
                    )
                    if ip_object:
                        # Create an indicator for the IP address
                        ip_indicator_description = f"Indicator for IP {fanged_ip} extracted from C2 URL {fanged_url}, detected by {honeypot_type}"
                        ip_indicator = self.stix_utils.create_stix_entity(
                            "indicator",
                            name=f"Indicator for IP {fanged_ip}",
                            pattern_type="stix",
                            pattern=f"[ipv4-addr:value = '{parsed_ip}']",
                            description=ip_indicator_description,
                            valid_from=datetime.utcnow(),
                            custom_properties={
                                # "x_opencti_main_observable_type": "IPv4-Addr",
                                "x_opencti_labels": custom_labels
                            },
                        )
                        if ip_indicator:
                            # Create a relationship between the IP indicator and the IP object
                            self.stix_utils.create_relationship(
                                source_ref=ip_indicator,
                                target_ref=ip_object,
                                relationship_type="based-on",
                                custom_properties={"x_opencti_labels": custom_labels},
                            )

                        # Create a relationship between the IP and the URL
                        self.stix_utils.create_relationship(
                            source_ref=ip_object,
                            target_ref=url_object,
                            relationship_type="related-to",
                            custom_properties={"x_opencti_labels": custom_labels},
                        )
                else:
                    self.helper.log_info(
                        f"No IP address was found in the the URL parsed: {url}"
                    )

                # Create a new STIX File object with additional properties and an indicator for it
                file_description = f"File object downloaded from {fanged_url}, detected by {honeypot_type}"
                file_object = file_hash_mapping.get(sha256)
                if not file_object:
                    file_object = self.stix_utils.create_stix_entity(
                        "file",
                        hashes={
                            "SHA-256": sha256,
                            "SHA-1": sha1,
                            "MD5": md5,
                            "SHA-512": sha512,
                        },
                        size=file_size,
                        name=file_name,
                        mime_type=mime_type,
                        description=file_description,
                        custom_properties={
                            "x_opencti_type": "File",
                            "x_opencti_labels": custom_labels,
                        },
                    )
                    file_hash_mapping[sha256] = file_object

                    # Create an indicator pattern that includes all available hashes
                    pattern_elements = []
                    if sha256:
                        pattern_elements.append(f"[file:hashes.'SHA-256' = '{sha256}']")
                    if sha1:
                        pattern_elements.append(f"[file:hashes.'SHA-1' = '{sha1}']")
                    if md5:
                        pattern_elements.append(f"[file:hashes.'MD5' = '{md5}']")
                    if sha512:
                        pattern_elements.append(f"[file:hashes.'SHA-512' = '{sha512}']")

                    pattern = " OR ".join(pattern_elements)

                    # Create an indicator for the file
                    file_indicator_description = f"Indicator for file downloaded from {fanged_url}, detected by {honeypot_type}"
                    file_indicator = self.stix_utils.create_stix_entity(
                        "indicator",
                        name=f"Indicator for file downloaded from {fanged_url}",
                        pattern_type="stix",
                        pattern=pattern,
                        description=file_indicator_description,
                        valid_from=datetime.utcnow(),
                        custom_properties={
                            # "x_opencti_main_observable_type": "StixFile",
                            "x_opencti_labels": custom_labels
                        },
                    )

                    if file_indicator:
                        # Create a relationship between the file indicator and the file object
                        self.stix_utils.create_relationship(
                            source_ref=file_indicator,
                            target_ref=file_object,
                            relationship_type="based-on",
                            custom_properties={"x_opencti_labels": custom_labels},
                        )

                # Create a relationship between the URL and the File
                self.stix_utils.create_relationship(
                    source_ref=url_object,
                    target_ref=file_object,
                    relationship_type="related-to",
                    custom_properties={"x_opencti_labels": custom_labels},
                )

                # Extract additional C2 URLs, IPs, and SSH-RSA keys from the bash script
                if self.download_manager.is_bash_script(file_path):
                    self.helper.log_info(f"Processing bash script file: {file_path}")

                    # Read the content of the bash script
                    with open(file_path, "r") as file:
                        bash_content = file.read()

                    # Extract additional network indicators (IPs, URLs, SSH keys)
                    parsed_data = self.download_manager.extract_network_indicators(
                        bash_content
                    )
                    additional_urls = parsed_data.get("urls", [])
                    extracted_ips = parsed_data.get("ips", [])
                    # extracted_ssh_keys = parsed_data.get('ssh_keys', [])

                    # Log extracted data
                    if additional_urls:
                        self.helper.log_info(
                            f"Extracted additional C2 URLs from script: {additional_urls}"
                        )
                        new_urls.extend(additional_urls)

                    if extracted_ips:
                        for ip in extracted_ips:
                            fanged_ip = self.fang_indicator(ip)
                            ip_description = f"Extracted IP address {fanged_ip} from bash script, detected by {honeypot_type}"
                            ip_object = self.stix_utils.create_stix_entity(
                                "ipv4-addr",
                                value=ip,
                                description=ip_description,
                                custom_properties={
                                    "x_opencti_type": "IPv4-Addr",
                                    "x_opencti_labels": custom_labels,
                                },
                            )

                            # Create an indicator for the IP address
                            ip_indicator_description = f"Indicator for IP address {fanged_ip}, detected by {honeypot_type}"
                            ip_indicator = self.stix_utils.create_stix_entity(
                                "indicator",
                                name=f"Indicator for IP address {fanged_ip}",
                                pattern_type="stix",
                                pattern=f"[ipv4-addr:value = '{ip}']",
                                description=ip_indicator_description,
                                valid_from=datetime.utcnow(),
                                custom_properties={
                                    # "x_opencti_main_observable_type": "IPv4-Addr",
                                    "x_opencti_labels": custom_labels
                                },
                            )

                            if ip_indicator and ip_object:

                                # Create a relationship between the IP indicator and the IP object
                                self.stix_utils.create_relationship(
                                    source_ref=ip_indicator,
                                    target_ref=ip_object,
                                    relationship_type="based-on",
                                    custom_properties={
                                        "x_opencti_labels": custom_labels
                                    },
                                )

                                # Relate the IP to the file object
                                self.stix_utils.create_relationship(
                                    source_ref=file_object,
                                    target_ref=ip_object,
                                    relationship_type="indicates",
                                    custom_properties={
                                        "x_opencti_labels": custom_labels
                                    },
                                )

                processed_urls.add(url)

            current_urls = new_urls
        return processed_urls
