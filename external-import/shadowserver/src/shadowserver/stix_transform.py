import copy
import base64
from datetime import datetime
from stix2 import MarkingDefinition, Identity, Artifact, AutonomousSystem, Vulnerability, IPv4Address, IPv6Address, DomainName, MACAddress, NetworkTraffic, X509Certificate, ObservedData
from pycti import OpenCTIConnectorHelper, Identity as pycti_identity
import magic
from .utils import datetime_to_string, string_to_datetime, note_timestamp_to_datetime, dict_to_markdown, check_ip_address, from_list_to_csv, get_stix_id_precedence, calculate_hashes, find_stix_object_by_id

class ShadowServerStixTransformation:
    def __init__(self, marking_refs: MarkingDefinition, report_list: list, report: dict, api_helper: OpenCTIConnectorHelper, labels: list = ['ShadowServer']):
        self.helper = api_helper
        self.validate_inputs(marking_refs, report_list, report)
        self.type = report.get("type", None)
        self.url = report.get("url", None)
        self.report = report
        self.report_list = report_list
        self.labels = labels
        self.stix_objects = []
        self.object_refs = []
        self.custom_properties = {}
        self.external_reference = None
        self.author_id = None

        self.published = self.get_published_date(report_list)
        self.marking_refs = [marking_refs] if isinstance(marking_refs, MarkingDefinition) else []

        self.create_stix_objects()

    def create_stix_objects(self):
        """Creates STIX objects in OpenCTI."""
        self.create_author()
        self.create_external_reference()
        self.create_custom_properties()
        self.create_report()

    def create_custom_properties(self):
        """Creates custom properties in OpenCTI."""
        if self.external_reference:
            self.custom_properties["external_references"] = [self.external_reference]
        if self.author_id:
            self.custom_properties["created_by_ref"] = self.author_id
        if self.labels:
            self.custom_properties["x_opencti_labels"] = self.labels

    def handle_stix_object_creation(self, key:str, create_method, element:dict, labels:list = []):
        value = element.get(key)
        stix_object = None

        # Create the STIX object
        if value:
            self.helper.log_debug(f"Creating {key} STIX object: {value}")
            stix_object = create_method(value = value, labels = labels)
        
        # Add the STIX object to the list of objects
        if stix_object:
            self.helper.log_debug(f"Created {key} STIX object: {stix_object.get('id')}")
            self.object_refs.append(stix_object.get('id'))
            self.stix_objects.append(stix_object)
            return stix_object.get('id')
        elif stix_object is None and value:
            self.helper.log_error(f"Failed to create {key} STIX object: {value}")

    def validate_inputs(self, marking_refs, report_list, report):
        self.helper.log_debug("Validating inputs.")
        if not isinstance(marking_refs, MarkingDefinition):
            raise ValueError(f"Invalid marking references: {marking_refs}")
        if not isinstance(report_list, list) or not report_list:
            raise ValueError("Report list must be a non-empty list")
        if not isinstance(report, dict):
            raise ValueError("Report must be a dictionary")

    def get_published_date(self, report_list):
        self.helper.log_debug(f"Getting published date.")
        try:
            if report_list and isinstance(report_list[0], dict) and report_list[0].get("timestamp"):
                return datetime_to_string(string_to_datetime(report_list[0].get("timestamp")))
        except Exception as e:
            self.helper.log_error(f"Error parsing published date: {e}")
        return datetime_to_string(datetime.now())
        
    def get_stix_objects(self):
        return self.stix_objects
    
    def create_external_reference(self):
        self.helper.log_info(f"Creating external reference: ({self.url}).")
        self.external_reference = {
            "source_name": "source",
            "description": "ShadowServer Report",
            "url": f"{self.url}",
        }
    
    def create_opencti_case(self):
        self.helper.log_debug(f"Creating OpenCTI case: {self.report.get('id')}")
        description = str()
        for key, value in self.report.items():
            description += f"{key}: {value}\n"
        kwargs = {
            "name": f"ShadowServer Report {self.type}: {self.report.get('id')}",
            "description": description,
            "externalReferences": self.external_ref_id,
            "objectLabel": self.labels,
        }
        if isinstance(self.marking_refs, list) and len(self.marking_refs) > 0 and self.marking_refs[0].get('id'):
            kwargs.update(objectMarking=self.marking_refs[0].get('id'))
        if self.object_refs:
            kwargs.update(externalReferences=self.object_refs)
        opencti_obj = self.helper.api.case_incident.create(**kwargs)
        self.case_id = opencti_obj.get('id')
        self.object_refs.append(self.case_id)
    
    def upload_stix2_artifact(self, report_list):
        self.helper.log_debug(f"Uploading ShadowServer report as artifact.")
        csv_str_enc = from_list_to_csv(report_list).encode()
        mime_type = magic.from_buffer(csv_str_enc, mime=True)
        base64_encoded_str = base64.b64encode(csv_str_enc).decode('utf-8')

        kwargs = {
            "payload_bin": base64_encoded_str,
            "mime_type": mime_type,
            "type": "artifact",
            "hashes": calculate_hashes(csv_str_enc),
        }

        self.helper.log_info(f"Uploading ShadowServer report as artifact: {self.report}.")

        # Add custom properties
        custom_properties = copy.deepcopy(self.custom_properties)
        custom_properties["x_opencti_description"] = f"ShadowServer Report Type ({self.type}) Report ID ({self.report.get('id')})"
        custom_properties["x_opencti_additional_names"] = [self.report.get('file', 'default_file_name.csv')]
        custom_properties["x_opencti_score"] = 0 # Set score to 0 due to trusted source.

        # Add custom properties and marking definition
        if self.custom_properties:
            kwargs.update(custom_properties=custom_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

        # TODO: Delete this
        # Write the CSV string to a file
        try:
            with open(self.report.get('file', 'default_file_name.csv'), 'w') as file:
                file.write(csv_str_enc.decode())
        except Exception as e:
            self.helper.log_error(f"Failed to write CSV file to disk: {e}")
        # TODO: Delete to here.

        artifact = Artifact(**kwargs)

        if artifact.get('id'):
            self.artifact_id = artifact.get('id')
            self.stix_objects.append(artifact)
        else:
            self.helper.log_error(f"Failed to upload ShadowServer report as artifact: {self.report}.")


    def create_report(self):
        self.helper.log_debug(f"Creating report: {self.report.get('id')}")
        description = []
        self.upload_stix2_artifact(self.report_list)

        for element in self.report_list:
            description.append(dict_to_markdown(element))
            self.map_to_stix(element)
        # TODO: Creat OpenCTI case
        # self.create_opencti_case()
        
        # TODO: Create Report? 
        # self.stix_report = Report(
        #     id=pycti_report.generate_id(name=self.report.get("id"), published=self.published),
        #     report_types=['tool'],
        #     name=f"ShadowServer Report: {self.type}",
        #     published=self.published,
        #     object_refs = self.object_refs,
        #     external_references=[self.external_ref],
        #     description='\n---\n'.join(description),
        #     created_by_ref=self.author_id.id,
        #     object_marking_refs=self.marking_refs,
        #     labels = self.labels,
        # )
        # self.stix_objects.append(
        #     self.stix_report
        # )
    
    def add_default_labels(self, stix_obj: dict):
        """Adds default labels to the specified STIX object."""
        self.helper.log_debug(f"Adding default labels: {self.default_labels_id}")
        for label_id in self.default_labels_id:
            if isinstance(label_id, str) and stix_obj.get('id'):
                if 'Stix-Domain-Object' in stix_obj.get('parent_types'):
                    self.helper.api.stix_domain_object.add_label(
                        id=stix_obj.get('id'), label_id=label_id
                    )
                elif 'Stix-Cyber-Observable' in stix_obj.get('parent_types'):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=stix_obj.get('id'), label_id=label_id
                    )
                else:
                    self.helper.log_error(f"Invalid STIX object type: {stix_obj.get('parent_types')}")
            else:
                self.helper.log_error(f"Invalid label: {label_id}")

    def create_author(self):
        """Creates the author of the report."""
        self.helper.log_debug(f"Creating author: ShadowServer Connector")
        """Creates ShadowServer Author"""
        kwargs = {
            "id": pycti_identity.generate_id("ShadowServer Connector", "Organization"),
            "name": "ShadowServer Connector",
            "identity_class": "Organization",
            "type": "identity",
            "description": "ShadowServer Connector",
            "sectors": "non-profit",
        }

        # Add custom properties and marking definition
        if self.custom_properties:
            # Add custom properties to the author.
            customer_properties = copy.deepcopy(self.custom_properties)
            customer_properties["x_opencti_reliability"] = "A - Completely reliable" # TODO: Make it configurable
            customer_properties["x_opencti_organization_type"] = "non-profit"
            kwargs.update(custom_properties=customer_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

        # Create author
        author = Identity(
            **kwargs
            )

        if author.get('id'):
            self.author_id = author.get('id')
            self.stix_objects.append(author)

    def map_to_stix(self, element):
        # Define a mapping of object types to their creation functions
        object_types = {
            'asn': self.create_asn,
            'ip': self.create_ip,
            'hostname': self.create_hostname,
            'mac_address': self.create_mac_address,
        }
        self.helper.log_debug(f"Mapping ShadowServer report to STIX.")
        observed_data_list = list()
        labels_list = list()
        labels_list.extend(self.custom_properties.get('x_opencti_labels', []))

        # Get tags from the report, create labels, and vulnerability.
        if element.get('tag') and ";" in element.get('tag'):
            custom_labels = element.get('tag').split(';')
            for labels in custom_labels:
                if isinstance(labels, str) and labels.upper().startswith('CVE'):
                    self.helper.log_debug(f"Label is CVE: {labels}")
                    self.create_vulnerability(labels)
            if len(custom_labels) > 0:
                labels_list.extend(custom_labels)
        self.helper.log_debug(f"Labels: {labels_list}")
        # Iterate over the mapping and create STIX objects
        for object_type, create_function in object_types.items():
            stix_object_str = self.handle_stix_object_creation(object_type, create_function, element, labels_list)
            if isinstance(stix_object_str, str):
                self.helper.log_debug(f"Created {object_type} STIX object: {stix_object_str}")
                observed_data_list.append(stix_object_str)
        if element.get('port') and element.get('protocol'):
            dst_ref = get_stix_id_precedence(observed_data_list)
            stix_object_str = self.create_network_traffic(port=element.get('port'), protocol=element.get('protocol'), dst_ref=dst_ref, labels=labels_list)
            if isinstance(stix_object_str, str):
                self.helper.log_debug(f"Created network-traffic STIX object: {stix_object_str}")
                observed_data_list.append(stix_object_str)
        if element.get('cert_serial_number'):
            stix_object_str = self.create_x509_certificate(element, labels_list)
            if isinstance(stix_object_str, str):
                self.helper.log_debug(f"Created x509-certificate STIX object: {stix_object_str}")
                observed_data_list.append(stix_object_str)
        if observed_data_list:
            first_observed=note_timestamp_to_datetime(element.get('timestamp'))
            self.create_observed_data(
                observables_list=observed_data_list,
                labels_list=labels_list,
                first_observed=first_observed
                )
        else:
            self.helper.log_error(f"Unable to create observed data for element: {element}")

    def extend_stix_object(self, kwargs: dict, labels:list = []):
        """Extends the specified STIX object with custom properties and marking definitions."""
        # Add custom properties
        custom_properties = copy.deepcopy(self.custom_properties)
        # Add score
        custom_properties["x_opencti_score"] = 0
        # Add labels
        if len(labels) > 0:
            custom_properties["x_opencti_labels"] = labels
        # Add custom properties and marking definition
            kwargs.update(custom_properties=custom_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

    def create_vulnerability(self, name: str):
        """Creates a vulnerability STIX object."""
        self.helper.log_debug(f"Creating vulnerability STIX object: {name}")
        kwargs = {
            "type": "vulnerability",
            "name": name.upper(),
            "created_by_ref": self.author_id,
            "labels": self.labels,
            "external_references": [self.external_reference],
            "object_marking_refs": self.marking_refs,
        }

        opencti_obj = Vulnerability(**kwargs)

        # Add object to the STIX bundle
        if opencti_obj.get('id'):
            self.object_refs.append(opencti_obj.get('id'))
            self.stix_objects.append(opencti_obj)

    def create_asn(self, value: int, labels:list = []):
        """Creates an autonomous system STIX object."""
        self.helper.log_debug(f"Creating ASN STIX object: {value}")
        kwargs = {
            "type": "autonomous-system",
            "number": value,
        }
        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)
        return AutonomousSystem(**kwargs)

    def create_ip(self, value: str, labels:list = []):
        """Creates an IP address STIX object."""
        self.helper.log_debug(f"Creating IP STIX object: {value}")
        kwargs = {
            "value": value
        }
        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)
        
        if check_ip_address(value).startswith('IPv4'):
            kwargs["type"] = "ipv4-addr"
            return IPv4Address(**kwargs)
        elif check_ip_address(value).startswith('IPv6'):
            kwargs["type"] = "ipv6-addr"
            return IPv6Address(**kwargs)
        else:
            self.helper.log_error(f"Invalid IP address: {value}")
            return None
    
    def create_hostname(self, value: str, labels:list = []):
        """Creates a hostname STIX object."""
        self.helper.log_debug(f"Creating hostname STIX object: {value}")
        kwargs = {
            "type": "domain-name",
            "value": value,
        }
        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)
        return DomainName(**kwargs)

    def create_mac_address(self, value: str, labels:list = []):
        """Creates a MAC address STIX object."""
        self.helper.log_debug(f"value MAC address STIX object: {value}")
        kwargs = {
            "type": "mac-addr",
            "value": value,
        }
        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)
        return MACAddress(**kwargs)

    def create_network_traffic(self, port: int, protocol: str, dst_ref:str = None, labels: list = []):
        """Creates a network traffic STIX object."""
        self.helper.log_debug(f"Creating network traffic STIX object. Port: {port}, Protocol: {protocol}.")
        kwargs = {
            "type": "network-traffic",
            "dst_port": port,
            "protocols": [protocol],
            "dst_ref": dst_ref,
            "is_active": False,
            "start": self.published,
            "end": self.published,
        }

        dst_value = find_stix_object_by_id(self.stix_objects, dst_ref)
        self.helper.log_debug(f"Value of stix object: {dst_value}")

        description = f"Network Traffic {dst_value} - {protocol}:{port}"

        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)
        kwargs["custom_properties"].update(
            {
                'x_opencti_description': description
            }
        )

        # Create the STIX object
        stix_object = NetworkTraffic(**kwargs)

        # Add the STIX object to the list of objects
        if stix_object:
            self.helper.log_debug(f"Created network traffic STIX object: {stix_object.get('id')}")
            self.object_refs.append(stix_object.get('id'))
            self.stix_objects.append(stix_object)
            return stix_object.get('id')

    def create_x509_certificate(self, data: dict, labels: list = []):
        """Creates an X509 certificate STIX object."""
        self.helper.log_debug(f"Creating X509 certificate STIX object: {data}")
        kwargs = {
            "type": "x509-certificate",
        }
        # Remove unwanted characters from hashes
        hashes = {
                'SHA-1': data.get('sha1_fingerprint', None),
                'SHA-256': data.get('sha256_fingerprint', None),
                'SHA-512': data.get('sha512_fingerprint', None),
                'MD5': data.get('md5_fingerprint', None),
                # Include other hash types if available
            }
        cleaned_hashes = {k: v.replace(":", "") for k, v in hashes.items() if v is not None}
        kwargs.update(hashes=cleaned_hashes)

        # Convert timestamps to datetime
        if data.get('cert_issue_date'):
            validity_not_before = note_timestamp_to_datetime(data.get('cert_issue_date') + 'Z')
            kwargs.update(validity_not_before=validity_not_before)
        if data.get('cert_expiration_date'):
            validity_not_after = note_timestamp_to_datetime(data.get('cert_expiration_date') + 'Z')
            kwargs.update(validity_not_after=validity_not_after)

        if data.get('cert_serial_number'):
            kwargs.update(serial_number=data.get('cert_serial_number'))
        if data.get('signature_algorithm'):
            kwargs.update(signature_algorithm=data.get('signature_algorithm'))
        if data.get('issuer_common_name'):
            kwargs.update(issuer=data.get('issuer_common_name'))
        if data.get('subject_common_name'):
            kwargs.update(subject=data.get('subject_common_name'))

        # Add custom properties and marking definition
        self.extend_stix_object(kwargs, labels)

        # Create the STIX object
        stix_object = X509Certificate(**kwargs)

        # Add the STIX object to the list of objects
        if stix_object:
            self.helper.log_debug(f"Created X509 certificate STIX object: {stix_object.get('id')}")
            self.object_refs.append(stix_object.get('id'))
            self.stix_objects.append(stix_object)
            return stix_object.get('id')
    
    def create_observed_data(self, observables_list: list, labels_list: list, first_observed: datetime = datetime.now(), last_observed: datetime = None):
        """Creates an observed data STIX object."""
        self.helper.log_debug(f"Creating observed data STIX object: {observables_list}")
        try:
            observables = [obs for obs in observables_list if obs is not None]
            if not observables:
                return None

            first_observed = first_observed
            last_observed = last_observed or first_observed

            # Create observed data
            kwargs = {
                "object_refs": observables,  # Reference to the created observable
                "first_observed": first_observed.isoformat(timespec='milliseconds') + 'Z',
                "last_observed": last_observed.isoformat(timespec='milliseconds') + 'Z',
                "number_observed": len(observables),
            }

            # Add custom properties and marking definition
            self.extend_stix_object(kwargs, labels_list)
            # Create the STIX object
            stix_object = ObservedData(**kwargs)

            # Add the STIX object to the list of objects
            if stix_object:
                self.helper.log_debug(f"Created observed data STIX object: {stix_object.get('id')}")
                self.stix_objects.append(stix_object)
        except Exception as e:
            self.helper.log_error(f"Error creating observed data: {e}")




    # def create_stix_note_from_data(self):
    #     for element in self.report_list:
    #         content = dict_to_markdown(element)
    #         abstract = f'ShadowServer {self.type} Report {element.get("timestamp")}'
    #         stix_object = Note(
    #             id = pycti_note.generate_id(abstract, content),
    #             abstract=abstract,
    #             content=content,
    #             created=note_timestamp_to_datetime(element.get("timestamp")),
    #             created_by_ref=self.author_id.id,
    #             object_refs=[self.report_id],
    #             object_marking_refs=self.marking_refs,
    #             labels=self.labels,
    #             external_references=[self.external_ref],
    #         )
    #         self.stix_objects.append(stix_object)
    #         self.object_refs.append(stix_object.id)