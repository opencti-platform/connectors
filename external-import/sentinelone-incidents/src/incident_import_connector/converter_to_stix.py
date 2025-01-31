import stix2
from pycti import (
    AttackPattern,
    Identity,
    Incident,
    Indicator,
    Note,
    StixCoreRelationship,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="SentinelOne Incident Connector", identity_class="organization"
            ),
            name="SentinelOne Incident Connector",
            identity_class="organization",
            description="The SentinelOne Incident Connector",
        )
        return author

    def create_incident(self, incident_data, incident_id, s1_url):
        def convert_confidence(confidence):
            confidence_score = {"malicious": 80, "suspicious": 50, "N/A": 20}.get(
                confidence, "suspicious"
            )
            return confidence_score

        self.helper.log_debug("Attempting to create corresponding Stix Incident")

        machine = incident_data.get("agentRealtimeInfo", {}).get(
            "agentComputerName", "unknown"
        )
        account_name = incident_data.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = incident_data.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        description = (
            f"Threat detected on machine {machine} under account {account_name} (id: {account_id})."
            f"\nThreat Name: {incident_data['threatInfo']['threatName']}."
            f"\nMitigation Status: {incident_data['threatInfo']['mitigationStatusDescription']}."
        )
        labels = [
            indicator.get("category", "")
            for indicator in incident_data.get("indicators", [])
            if indicator.get("category", "") != ""
        ]

        external_s1_ref = stix2.ExternalReference(
            source_name="SentinelOne",
            url=f"{s1_url}incidents/threats/{incident_id}/overview",
            description="View Incident In SentinelOne",
        )

        name = incident_data.get("threatInfo", {}).get("threatName", "")
        created = incident_data.get("threatInfo", {}).get("identifiedAt", "")

        incident = stix2.Incident(
            id=Incident.generate_id(name, created),
            created_by_ref=self.author,
            type="incident",
            name=name,
            description=description,
            labels=labels,
            confidence=convert_confidence(
                incident_data.get("threatInfo", {}).get("confidenceLevel", "suspicious")
            ),
            created=created,
            external_references=[external_s1_ref] if external_s1_ref else None,
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"source": self.author.name},
        )

        return [incident]

    def create_endpoint_observable(self, s1_incident, cti_incident_id):

        self.helper.log_debug("Attempting to create Endpoint Observable")

        endpoint_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "agentComputerName", ""
        )
        if not endpoint_name:
            return None

        account_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        desc = f"Affected Host on SentinelOne Account {account_name} (with id: {account_id})"

        endpoint_observable = stix2.UserAccount(
            account_type="hostname",
            user_id=endpoint_name,
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"description": desc},
        )

        endpoint_relationship = self.create_relationship(
            endpoint_observable["id"], cti_incident_id, "related-to"
        )

        return [endpoint_observable, endpoint_relationship]

    def create_attack_patterns(self, incident_data, cti_incident_id):

        def create_mitre_reference(technique):
            mitre_ref = stix2.ExternalReference(
                source_name="MITRE ATT&CK",
                url=technique.get("link"),
                external_id=technique.get("name"),
            )
            return mitre_ref

        self.helper.log_debug("Attempting to create Stix Attack Patterns")

        attack_patterns = []

        for pattern in incident_data.get("indicators", []):
            pattern_name = (
                pattern.get("category", "")
                + ": "
                + ", ".join(
                    [
                        tactic.get("name", "")
                        for tactic in pattern.get("tactics", [])
                        if tactic.get("name", "") != ""
                    ]
                )
            )

            attack_pattern = stix2.AttackPattern(
                id=AttackPattern.generate_id(pattern_name),
                created_by_ref=self.author,
                name=pattern_name,
                description=pattern.get("description", ""),
                object_marking_refs=[stix2.TLP_RED.id],
            )

            for tactic in pattern.get("tactics", []):
                sub_desc = ", ".join(
                    [
                        technique.get("name", "")
                        for technique in tactic.get("techniques", [])
                        if technique.get("name", "") != ""
                    ]
                )

                sub_name = "[sub] " + tactic.get("name", "")
                sub_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(sub_name),
                    created_by_ref=self.author,
                    name=sub_name,
                    description=sub_desc,
                    external_references=[
                        create_mitre_reference(technique)
                        for technique in tactic.get("techniques", [])
                    ],
                    object_marking_refs=[stix2.TLP_RED.id],
                )

                attack_patterns.append(sub_pattern)
                attack_patterns.append(
                    self.create_relationship(cti_incident_id, sub_pattern["id"], "uses")
                )

            attack_patterns.append(attack_pattern)
            attack_patterns.append(
                self.create_relationship(cti_incident_id, attack_pattern["id"], "uses")
            )

        return attack_patterns

    def create_notes(self, s1_notes, cti_incident_id):

        self.helper.log_debug("Attempting to create Stix Notes")

        incident_notes = []
        for note in s1_notes:
            content = note.get("text", "") + "\ncreated by: " + note.get("creator", "")
            created = note.get("createdAt", "")
            incident_note = stix2.Note(
                id=Note.generate_id(content=content, created=created),
                created_by_ref=self.author,
                content=content,
                object_refs=[cti_incident_id],
                object_marking_refs=[stix2.TLP_RED.id],
            )
            incident_notes.append(incident_note)

        return incident_notes

    def create_hash_indicators(self, s1_incident, cti_incident_id):

        self.helper.log_debug("Attempting to create Indicators")

        available_patterns = []
        hash_types = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}
        threat_info = s1_incident.get("threatInfo", {})

        for hash_key, hash_label in hash_types.items():
            if threat_info.get(hash_key):
                available_patterns.append(
                    f"[file:hashes.'{hash_label}'='{threat_info[hash_key]}']"
                )

        indicators = []
        for pattern in available_patterns:
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                created_by_ref=self.author,
                pattern=pattern,
                name="Malicious File Hash Indicator",
                pattern_type="stix",
                object_marking_refs=[stix2.TLP_RED.id],
            )
            indicators.append(
                self.create_relationship(cti_incident_id, indicator["id"], "related-to")
            )
            indicators.append(indicator)

        return indicators

    def create_relationship(self, parent_id, child_id, relationship_type):
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, parent_id, child_id),
            created_by_ref=self.author,
            relationship_type=relationship_type,
            source_ref=parent_id,
            target_ref=child_id,
            object_marking_refs=[stix2.TLP_RED.id],
        )
        return relationship
