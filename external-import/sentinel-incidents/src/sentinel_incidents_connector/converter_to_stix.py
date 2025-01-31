import stix2
import stix2.exceptions
from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Identity,
    Incident,
    Malware,
    StixCoreRelationship,
)

from .utils import CASE_INCIDENT_PRIORITIES, format_datetime, is_ipv4


def handle_stix2_error(decorated_function):
    """
    Decorate ConverterToStix instance method to handle STIX 2.1 exceptions.
    In case of an exception, log the error and return None.
    :param decorated_function: Method to decorate
    :return: Decorated method
    """

    def decorator(self, *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config, tlp_marking):
        self.helper = helper
        self.config = config
        self.tlp_marking = tlp_marking
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="organization",
            description="Import incidents according to alerts found in Microsoft Sentinel",
        )
        self.all_hashes = set()

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> dict:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects
        :param name: Author's name (i.e. connector's name)
        :param identity_class: Type of entity described
        :param description: Author's description
        :return: Identity in STIX 2.1 format
        """
        author = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class=identity_class),
            name=name,
            identity_class=identity_class,
            description=description,
        )
        return author

    @handle_stix2_error
    def create_incident(self, alert: dict) -> stix2.Incident | None:
        incident_name = alert.get("title")
        incident_created_at = format_datetime(alert.get("createdDateTime"))
        incident_modified_at = format_datetime(alert.get("lastUpdateDateTime"))
        incident_labels = [alert.get("category")] if alert.get("category") else None
        incident_description = (
            alert.get("description", "")
            + "\n\nRecommanded Actions:\n\n"
            + alert.get("recommendedActions", "")
        )

        stix_incident = stix2.Incident(
            id=Incident.generate_id(incident_name, incident_created_at),
            created=incident_created_at,
            modified=incident_modified_at,
            name=incident_name,
            labels=incident_labels,
            description=incident_description,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "url": alert.get("alertWebUrl"),
                    "external_id": alert.get("id"),
                }
            ],
            custom_properties={
                "source": self.config.target_product.replace("Azure", "Microsoft"),
                "severity": alert.get("severity"),
                "incident_type": "alert",
            },
        )
        return stix_incident

    @handle_stix2_error
    def create_custom_case_incident(
        self, incident: dict, bundle_objects: list[object]
    ) -> CustomObjectCaseIncident | None:
        """
        Create STIX 2.1 Custom Case Incident object
        :param incident: Incident to create Case Incident from
        :param bundle_objects: List of all the STIX 2.1 objects refering to the incident
        :return: Case Incident in STIX 2.1 format
        """
        case_incident_name = incident.get("displayName")
        case_incident_created_at = format_datetime(incident.get("createdDateTime"))
        case_incident_description = (
            "Incident from "
            + self.config.target_product.replace("Azure", "Microsoft")
            + " | classification: "
            + incident.get("classification", "")
            + " | determination: "
            + incident.get("determination", "")
        )

        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(case_incident_name, case_incident_created_at),
            name=case_incident_name,
            description=case_incident_description,
            severity=incident.get("severity"),
            priority=CASE_INCIDENT_PRIORITIES[incident.get("severity")],
            created=case_incident_created_at,
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "external_id": incident.get("id"),
                    "url": incident.get("incidentWebUrl"),
                }
            ],
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            object_refs=bundle_objects,
        )
        return stix_case

    @handle_stix2_error
    def create_evidence_user_account(self, evidence: dict) -> stix2.UserAccount | None:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        user_account_dict = evidence.get("userAccount")
        if not isinstance(user_account_dict, dict):
            self.helper.connector_logger.error(
                "This evidence does not contain user account's details: ",
                {"evidence": evidence},
            )
            return None

        user_account = stix2.UserAccount(
            account_login=user_account_dict.get("accountName"),
            display_name=user_account_dict.get("displayName"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return user_account

    @handle_stix2_error
    def create_evidence_ipv4(self, evidence: dict) -> stix2.IPv4Address | None:
        """
        Create STIX 2.1 IPv4 Address object
        :param evidence: Evidence to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ip_address = evidence.get("ipAddress")
        if not is_ipv4(ip_address):
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 address: ",
                {"value": ip_address},
            )
            return None

        ipv4 = stix2.IPv4Address(
            value=ip_address,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    @handle_stix2_error
    def create_evidence_url(self, evidence: dict) -> stix2.URL | None:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        stix_url = stix2.URL(
            value=evidence.get("url"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_url

    @handle_stix2_error
    def create_evidence_file(
        self, evidence: dict, stix_directory: stix2.Directory
    ) -> stix2.File | None:
        """
        Create a STIX 2.1 File object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and fileHashEvidence

        :param evidence: A dictionary containing evidence related to the File.
        :param stix_directory: A STIX `Directory` object representing the file's directory.
        :return: A STIX `File` object representing the file described in the evidence (if valid hashes are found)
        or None
        """
        hashes_mapping = {
            "md5": "MD5",
            "sha1": "SHA-1",
            "sha256": "SHA-256",
        }
        hashes = {}
        file = (
            evidence.get("imageFile")
            or evidence.get("fileDetails")
            or evidence.get("value")
        )

        # processEvidence & fileEvidence
        if isinstance(file, dict):
            for algorithm, hash_name in hashes_mapping.items():
                file_hash = file.get(algorithm)
                if file_hash:
                    hashes[hash_name] = file_hash
                    self.all_hashes.add(file_hash)
                else:
                    continue

        # fileHashEvidence
        if isinstance(file, str):
            algorithm = evidence.get("algorithm")
            if algorithm and file not in self.all_hashes:
                hashes[algorithm] = file
                self.all_hashes.add(file)
            else:
                return None

        if hashes:
            stix_file = stix2.File(
                hashes=hashes,
                name=file.get("fileName") if isinstance(file, dict) else None,
                size=file.get("fileSize") if isinstance(file, dict) else None,
                parent_directory_ref=stix_directory,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
            return stix_file
        else:
            return None

    @handle_stix2_error
    def create_evidence_custom_observable_hostname(
        self, evidence: dict
    ) -> CustomObservableHostname | None:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param evidence: Evidence to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        stix_hostname = CustomObservableHostname(
            value=evidence.get("deviceDnsName"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_hostname

    @handle_stix2_error
    def create_mitre_attack_pattern(self, technique: str) -> stix2.AttackPattern | None:
        """
        Create STIX 2.1 Attack Pattern object
        :param technique: Mitre Attack Pattern name
        :return: Attack Pattern in STIX 2.1 format
        """
        stix_attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique, technique),
            name=technique,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_mitre_id": technique,
                "created_by_ref": self.author["id"],
            },
        )
        return stix_attack_pattern

    @handle_stix2_error
    def create_evidence_malware(
        self, evidence: dict, sample_refs: list
    ) -> stix2.Malware | None:
        """
        Create a STIX 2.1 Malware object based on the provided evidence.
        Evidence type: malwareEvidence

        :param sample_refs: A list of references to sample files (file hashes) associated with
                            the malware. If no samples are provided, this will be set to `None`.
        :param evidence: A dictionary containing evidence related to the malware.
        :return: A STIX 2.1 Malware object representing the malware described in the evidence.
        """
        malware_name = evidence.get("name")
        malware_created = format_datetime(evidence.get("createdDateTime"))

        stix_malware = stix2.Malware(
            id=Malware.generate_id(malware_name),
            name=malware_name,
            is_family=False,
            malware_types=evidence.get("category"),
            sample_refs=sample_refs if len(sample_refs) != 0 else None,
            created=malware_created,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_malware

    @handle_stix2_error
    def create_evidence_directory(self, evidence: dict) -> stix2.Directory | None:
        """
        Create a STIX 2.1 Directory object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and malwareEvidence

        :param evidence: A dictionary containing evidence related to the directory.
        :return: A STIX 2.1 Directory object representing the directory described in the evidence.
        """
        # ! Sometimes Sentinel returns an empty string for the file path but stix2 lib doesn't check strings length
        file_path = evidence.get("filePath")
        if not file_path:
            return None

        stix_directory = stix2.Directory(
            path=file_path,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_directory

    @handle_stix2_error
    def create_relationship(
        self, source_id=None, target_id=None, relationship_type=None
    ) -> stix2.Relationship | None:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship in STIX 2.1 format
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
        )
        return relationship
