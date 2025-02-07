import uuid

import stix2
from pycti import Location


class StixUtils:
    def __init__(
        self,
        helper,
        tlp_marking,
        stix_labels,
        likelihood_notes=0,
        author_identity=None,
        update_existing_data=False,
    ):
        self.author_identity = None  # Initialize as None
        self.helper = helper  # Store the helper for loggin
        self.tlp_marking = tlp_marking
        self.stix_labels = stix_labels
        self.likelihood_notes = likelihood_notes
        self.update_existing_data = update_existing_data
        self.indicator_cache = {}
        self.stix_objects = []  # Maintain a list of created STIX objects

    def fang_indicator(self, indicator):
        """Fangs the given indicator to make it safe for sharing."""
        return indicator.replace(".", "[.]").replace(":", "[:]")

    def create_identity(self, author_name):
        """Create an identity object for the STIX2 bundle."""
        """Create and store the author identity."""

        self.author_identity = stix2.Identity(
            name=author_name,
            identity_class="organization",
            custom_properties={
                "revoked": False,
                "confidence": 100,
                "x_opencti_reliability": "B - Usually reliable",
                "x_opencti_organization_type": "csirt",
                "x_opencti_type": "Organization",
                "object_marking_refs": [self.tlp_marking["id"]],
            },
            allow_custom=True,
        )
        self.stix_objects.append(self.author_identity)  # Store in STIX objects
        return self.author_identity

    def create_stix_entity(
        self, entity_type, description=None, custom_properties=None, **kwargs
    ):
        """Create a STIX entity with specified properties."""
        if custom_properties is None:
            custom_properties = {}

        default_properties = {
            "x_opencti_score": 90,
            "x_opencti_detection": False,
            "x_mitre_platforms": ["linux"],
            "x_opencti_id": str(uuid.uuid4()),
            "x_opencti_created_by_ref": self.author_identity["id"],
            "x_opencti_labels": self.stix_labels,
            "object_marking_refs": [self.tlp_marking["id"]],
        }
        custom_properties = {**default_properties, **custom_properties}

        entity = None
        if entity_type == "ipv4-addr":
            entity = stix2.IPv4Address(
                description=description,
                custom_properties=custom_properties,
                allow_custom=True,
                **kwargs,
            )
        elif entity_type == "url":
            entity = stix2.URL(
                description=description,
                custom_properties=custom_properties,
                allow_custom=True,
                **kwargs,
            )
        elif entity_type == "file":
            entity = stix2.File(
                description=description,
                custom_properties=custom_properties,
                allow_custom=True,
                **kwargs,
            )
        elif entity_type == "indicator":
            pattern = kwargs.pop("pattern", None)
            entity = stix2.Indicator(
                description=description,
                pattern_type=kwargs.pop("pattern_type", "stix"),
                pattern=pattern,
                labels=self.stix_labels,
                custom_properties=custom_properties,
                allow_custom=True,
                indicator_types=kwargs.pop("indicator_types", None),
                valid_from=kwargs.pop("valid_from", None),
                created=kwargs.pop("created", None),
                **kwargs,
            )
            self.indicator_cache[pattern] = entity
        elif entity_type == "observed-data":
            entity = stix2.ObservedData(
                description=description,
                custom_properties=custom_properties,
                allow_custom=True,
                **kwargs,
            )
        else:
            raise ValueError(f"Unsupported entity type: {entity_type}")

        if entity:
            self.stix_objects.append(entity)
            self.helper.log_info(
                f"Created STIX entity of type {entity_type}: {entity.serialize()}"
            )
            return entity

    def create_relationship(
        self, source_ref, target_ref, relationship_type, custom_properties=None
    ):
        """Create a STIX relationship and add it to the centralized bundle."""
        rel = stix2.Relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            created_by_ref=self.author_identity["id"],
            object_marking_refs=[self.tlp_marking["id"]],
            labels=self.stix_labels,
            custom_properties=custom_properties or {},
            allow_custom=True,
        )
        self.stix_objects.append(rel)
        return rel

    def _generate_stix_asn(self, geoip_data):
        entity_asn = geoip_data.get("as_org", "Unknown ASN")
        asn_number = geoip_data.get("asn", 0)

        stix_asn = stix2.AutonomousSystem(
            type="autonomous-system",
            number=asn_number,
            name=entity_asn,
            custom_properties={
                "x_opencti_labels": ["asn"],
                "x_opencti_created_by_ref": self.author_identity["id"],
                "x_opencti_score": 90,
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )
        self.stix_objects.append(stix_asn)

        return stix_asn

    def _generate_stix_location(self, geoip_data, src_ip_object):
        # self.stix_objects = []

        # Generate City Location
        if "city_name" in geoip_data:
            stix_city_location = stix2.Location(
                id=Location.generate_id(geoip_data["city_name"], "City"),
                name=geoip_data["city_name"],
                country=geoip_data["country_name"],
                latitude=geoip_data.get("latitude"),
                longitude=geoip_data.get("longitude"),
                custom_properties={"x_opencti_location_type": "City"},
            )
            self.stix_objects.append(stix_city_location)

            self.create_relationship(
                src_ip_object["id"], stix_city_location["id"], relationship_type="located-at"
            )

        # Generate Country Location
        stix_country_location = stix2.Location(
            id=Location.generate_id(geoip_data["country_name"], "Country"),
            name=geoip_data["country_name"],
            country=geoip_data["country_name"],
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [geoip_data.get("country_code2", "Unknown")],
            },
        )
        self.stix_objects.append(stix_country_location)

        if not geoip_data.get("city_name"):
            self.create_relationship(
                src_ip_object["id"],
                stix_country_location["id"],
                relationship_type="located-at",
            )

        if "city_name" in geoip_data:
            self.create_relationship(
                stix_city_location["id"],
                stix_country_location["id"],
                relationship_type="located-at",
            )

    def create_or_find_note(
        self, fanged_attacker_commands, src_ip_object, indicator_src_ip
    ):

        # Query OpenCTI to check if the note already exists
        existing_note = self.helper.api.note.read(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "content",
                        "values": [fanged_attacker_commands],
                        "operator": "eq",
                        "mode": "or",
                    }
                ],
                "filterGroups": [],
            }
        )

        if existing_note:
            self.helper.log_info(
                "Note already exists in OpenCTI, linking it to new observables and indicators."
            )
            # Extract and validate the ID
            existing_note_id = existing_note.get("id")
            if not existing_note_id:
                self.helper.log_error(
                    "Existing note found but does not have an 'id'. Skipping..."
                )
            else:
                # Ensure the ID starts with 'note--'
                if not existing_note_id.startswith("note--"):
                    self.helper.log_info(f"ID before normalization: {existing_note_id}")
                    existing_note_id = f"note--{existing_note_id}"
                    self.helper.log_info(f"Normalized Note ID: {existing_note_id}")

                # Safely get the content
                note_content = existing_note.get("content", "")

                # Add relationship to the existing Note in opencti to the
                note_object = stix2.Note(
                    id=existing_note_id,
                    content=note_content,
                    object_refs=[
                        src_ip_object["id"],
                        indicator_src_ip["id"],
                    ],  # Required field
                    created_by_ref=self.author_identity["id"],
                    labels=self.stix_labels,
                    object_marking_refs=[self.tlp_marking["id"]],
                    allow_custom=True,
                )
                self.stix_objects.append(note_object)

                # Create relationships between the new note and the observables/indicators
                # for observable_ref in [src_ip_object, indicator_src_ip]:
                #    self.create_relationship(note_object.id, observable_ref.id, "related-to")

        else:
            self.helper.log_info(
                f"This note: {existing_note} was not found in opencti let's try to find any duplicates in Stix Bundle"
            )

            # First, check if a note with the same content already exists in the STIX bundle (self.stix_objects list)
            # Check if a note with the same content already exists in the STIX bundle (self.stix_objects list)
            duplicate_found = False

            for stix_object in self.stix_objects:
                if (
                    isinstance(stix_object, stix2.Note)
                    and stix_object.content == fanged_attacker_commands
                ):
                    self.helper.log_info(
                        "Note with the same content already exists in the STIX bundle."
                    )

                    # Create relationships between the existing note in the STIX bundle and the observables/indicators
                    for observable_ref in [src_ip_object, indicator_src_ip]:
                        observable_id = (
                            observable_ref
                            if isinstance(observable_ref, str)
                            else observable_ref["id"]
                        )
                        self.create_relationship(
                            stix_object["id"], observable_id, "related-to"
                        )

                    duplicate_found = True
                    break  # Exit loop as soon as a duplicate is found
                    # If no duplicate was found, create a new note

            # If no duplicate was found, create a new note
            if not duplicate_found:
                self.helper.log_info(
                    f"Creating a new note for commands: {fanged_attacker_commands}"
                )

                # Create the new note object
                note_object = stix2.Note(
                    abstract="Command left by attackers",
                    content=fanged_attacker_commands,
                    object_refs=[src_ip_object["id"], indicator_src_ip["id"]],
                    created_by_ref=self.author_identity["id"],
                    labels=self.stix_labels,
                    object_marking_refs=[self.tlp_marking["id"]],
                    likelihood=int(self.likelihood_notes),
                    custom_properties={
                        "x_opencti_type": "Note",
                        "x_opencti_labels": self.stix_labels + ["attacker-commands"],
                        "note_types": ["internal"],
                    },
                    allow_custom=True,
                    update=self.update_existing_data,
                )
                self.stix_objects.append(note_object)

                # Create relationships between the new note and the observables/indicators
                for observable_ref in [src_ip_object, indicator_src_ip]:
                    self.create_relationship(
                        note_object["id"], observable_ref["id"], "related-to"
                    )

    def get_stix_bundle(self):
        """Retrieve the centralized STIX bundle."""
        return stix2.Bundle(objects=self.stix_objects, allow_custom=True)
