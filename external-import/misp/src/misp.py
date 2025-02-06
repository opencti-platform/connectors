import json
import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime

import pytz
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    CustomObservablePhoneNumber,
    CustomObservableText,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    StixSightingRelationship,
    Tool,
    get_config_variable,
)
from pymisp import PyMISP

PATTERNTYPES = ["yara", "sigma", "pcre", "snort", "suricata"]
OPENCTISTIX2 = {
    "autonomous-system": {
        "type": "autonomous-system",
        "path": ["number"],
        "transform": {"operation": "remove_string", "value": "AS"},
    },
    "mac-addr": {"type": "mac-addr", "path": ["value"]},
    "hostname": {"type": "hostname", "path": ["value"]},
    "domain": {"type": "domain-name", "path": ["value"]},
    "ipv4-addr": {"type": "ipv4-addr", "path": ["value"]},
    "ipv6-addr": {"type": "ipv6-addr", "path": ["value"]},
    "url": {"type": "url", "path": ["value"]},
    "link": {"type": "url", "path": ["value"]},
    "email-address": {"type": "email-addr", "path": ["value"]},
    "email-subject": {"type": "email-message", "path": ["subject"]},
    "mutex": {"type": "mutex", "path": ["name"]},
    "file-name": {"type": "file", "path": ["name"]},
    "file-path": {"type": "file", "path": ["name"]},
    "file-md5": {"type": "file", "path": ["hashes", "MD5"]},
    "file-sha1": {"type": "file", "path": ["hashes", "SHA-1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA-256"]},
    "directory": {"type": "directory", "path": ["path"]},
    "registry-key": {"type": "windows-registry-key", "path": ["key"]},
    "registry-key-value": {"type": "windows-registry-value-type", "path": ["data"]},
    "pdb-path": {"type": "file", "path": ["name"]},
    "x509-certificate-issuer": {"type": "x509-certificate", "path": ["issuer"]},
    "x509-certificate-serial-number": {
        "type": "x509-certificate",
        "path": ["serial_number"],
    },
    "text": {"type": "text", "path": ["value"]},
    "user-agent": {"type": "user-agent", "path": ["value"]},
    "phone-number": {"type": "phone-number", "path": ["value"]},
    "user-account": {"type": "user-account", "path": ["account_login"]},
    "user-account-github": {
        "type": "user-account",
        "path": ["account_login"],
        "account_type": "github",
    },
    "identity-individual": {"type": "identity", "identity_class": "individual"},
}
FILETYPES = ["file-name", "file-md5", "file-sha1", "file-sha256"]

marking_tlp_clear = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:CLEAR",
)

marking_pap_clear = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("PAP", "PAP:CLEAR"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:CLEAR",
)

marking_pap_green = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("PAP", "PAP:GREEN"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:GREEN",
)

marking_pap_amber = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("PAP", "PAP:AMBER"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:AMBER",
)

marking_pap_red = stix2.MarkingDefinition(
    id=MarkingDefinition.generate_id("PAP", "PAP:RED"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:RED",
)


def is_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def filter_event_attributes(event, **filters):
    if not filters:
        return None

    attributes = list()
    for attribute in event["Event"]["Attribute"]:
        for key, value in filters.items():
            if attribute[key] != value:
                break
        else:
            attributes.append(attribute)
    return attributes


def parse_filter_config(config):
    filters = dict()

    if not config:
        return filters

    for item in config.split(","):
        key, value = item.split("=")
        filters[key] = value

    return filters


class Misp:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.misp_url = get_config_variable("MISP_URL", ["misp", "url"], config)
        self.misp_reference_url = get_config_variable(
            "MISP_REFERENCE_URL", ["misp", "reference_url"], config
        )
        self.misp_key = get_config_variable("MISP_KEY", ["misp", "key"], config)
        self.misp_ssl_verify = get_config_variable(
            "MISP_SSL_VERIFY", ["misp", "ssl_verify"], config
        )
        self.misp_client_cert = get_config_variable(
            "MISP_CLIENT_CERT", ["misp", "client_cert"], config
        )
        self.misp_datetime_attribute = get_config_variable(
            "MISP_DATETIME_ATTRIBUTE",
            ["misp", "datetime_attribute"],
            config,
            default="timestamp",
        )
        self.misp_filter_date_attribute = get_config_variable(
            "MISP_DATE_FILTER_FIELD",
            ["misp", "date_filter_field"],
            config,
            default="timestamp",
        )
        self.misp_report_description_attribute_filter = parse_filter_config(
            get_config_variable(
                "MISP_REPORT_DESCRIPTION_ATTRIBUTE_FILTER",
                ["misp", "report_description_attribute_filter"],
                config,
                # "type=comment,category=Internal reference"
            )
        )

        self.misp_create_reports = get_config_variable(
            "MISP_CREATE_REPORTS", ["misp", "create_reports"], config
        )
        self.misp_create_indicators = get_config_variable(
            "MISP_CREATE_INDICATORS", ["misp", "create_indicators"], config
        )
        self.misp_create_observables = get_config_variable(
            "MISP_CREATE_OBSERVABLES", ["misp", "create_observables"], config
        )
        self.misp_create_object_observables = get_config_variable(
            "MISP_CREATE_OBJECT_OBSERVABLES",
            ["misp", "create_object_observables"],
            config,
            default=False,
        )
        self.misp_create_tags_as_labels = get_config_variable(
            "MISP_CREATE_TAGS_AS_LABELS",
            ["misp", "create_tags_as_labels"],
            config,
            default=True,
        )
        self.misp_guess_threats_from_tags = get_config_variable(
            "MISP_GUESS_THREAT_FROM_TAGS",
            ["misp", "guess_threats_from_tags"],
            config,
            default=False,
        )
        self.misp_author_from_tags = get_config_variable(
            "MISP_AUTHOR_FROM_TAGS",
            ["misp", "author_from_tags"],
            config,
            default=False,
        )
        self.misp_markings_from_tags = get_config_variable(
            "MISP_MARKINGS_FROM_TAGS",
            ["misp", "markings_from_tags"],
            config,
            default=False,
        )
        self.keep_original_tags_as_label = get_config_variable(
            "MISP_KEEP_ORIGINAL_TAGS_AS_LABEL",
            ["misp", "keep_original_tags_as_label"],
            config,
            default="",
        ).split(",")
        self.helper.log_info(
            f"keep_original_tags_as_label: {self.keep_original_tags_as_label}"
        )
        self.misp_enforce_warning_list = get_config_variable(
            "MISP_ENFORCE_WARNING_LIST",
            ["misp", "enforce_warning_list"],
            config,
            default=False,
        )
        self.misp_report_type = get_config_variable(
            "MISP_REPORT_TYPE", ["misp", "report_type"], config, False, "misp-event"
        )
        self.misp_import_from_date = get_config_variable(
            "MISP_IMPORT_FROM_DATE", ["misp", "import_from_date"], config
        )
        self.misp_import_tags = get_config_variable(
            "MISP_IMPORT_TAGS", ["misp", "import_tags"], config
        )
        self.misp_import_tags_not = get_config_variable(
            "MISP_IMPORT_TAGS_NOT", ["misp", "import_tags_not"], config
        )
        self.misp_import_creator_orgs = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS", ["misp", "import_creator_orgs"], config
        )
        self.misp_import_creator_orgs_not = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS_NOT", ["misp", "import_creator_orgs_not"], config
        )
        self.misp_import_owner_orgs = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS", ["misp", "import_owner_orgs"], config
        )
        self.misp_import_owner_orgs_not = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS_NOT", ["misp", "import_owner_orgs_not"], config
        )
        self.misp_import_keyword = get_config_variable(
            "MISP_IMPORT_KEYWORD", ["misp", "MISP_IMPORT_KEYWORD"], config
        )
        self.import_distribution_levels = get_config_variable(
            "MISP_IMPORT_DISTRIBUTION_LEVELS",
            ["misp", "import_distribution_levels"],
            config,
        )
        self.import_threat_levels = get_config_variable(
            "MISP_IMPORT_THREAT_LEVELS", ["misp", "import_threat_levels"], config
        )
        self.import_only_published = get_config_variable(
            "MISP_IMPORT_ONLY_PUBLISHED", ["misp", "import_only_published"], config
        )
        self.import_with_attachments = bool(
            get_config_variable(
                "MISP_IMPORT_WITH_ATTACHMENTS",
                ["misp", "import_with_attachments"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.import_to_ids_no_score = get_config_variable(
            "MISP_IMPORT_TO_IDS_NO_SCORE",
            ["misp", "import_to_ids_no_score"],
            config,
            isNumber=True,
        )
        self.import_unsupported_observables_as_text = bool(
            get_config_variable(
                "MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT",
                ["misp", "import_unsupported_observables_as_text"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.import_unsupported_observables_as_text_transparent = bool(
            get_config_variable(
                "MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT",
                ["misp", "import_unsupported_observables_as_text_transparent"],
                config,
                isNumber=False,
                default=True,
            )
        )
        self.misp_interval = get_config_variable(
            "MISP_INTERVAL", ["misp", "interval"], config, isNumber=True
        )

        # Initialize MISP
        self.misp = PyMISP(
            url=self.misp_url,
            key=self.misp_key,
            cert=self.misp_client_cert,
            ssl=self.misp_ssl_verify,
            debug=False,
            tool="OpenCTI MISP connector",
        )

    def get_interval(self):
        return int(self.misp_interval) * 60

    def run(self):
        while True:
            now = datetime.now(pytz.UTC)
            friendly_name = "MISP run @ " + now.astimezone(pytz.UTC).isoformat()
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if (
                current_state is not None
                and "last_run" in current_state
                and "last_event_timestamp" in current_state
                and "last_event" in current_state
            ):
                last_run = parse(current_state["last_run"])
                last_event = parse(current_state["last_event"])
                last_event_timestamp = current_state["last_event_timestamp"]
                self.helper.log_info(
                    "Connector last run: " + last_run.astimezone(pytz.UTC).isoformat()
                )
                self.helper.log_info(
                    "Connector latest event: "
                    + last_event.astimezone(pytz.UTC).isoformat()
                )
            elif current_state is not None and "last_run" in current_state:
                last_run = parse(current_state["last_run"])
                last_event = last_run
                last_event_timestamp = int(last_event.timestamp())
                self.helper.log_info(
                    "Connector last run: " + last_run.astimezone(pytz.UTC).isoformat()
                )
                self.helper.log_info(
                    "Connector latest event: "
                    + last_event.astimezone(pytz.UTC).isoformat()
                )
            else:
                if self.misp_import_from_date is not None:
                    last_event = parse(self.misp_import_from_date)
                    last_event_timestamp = int(last_event.timestamp())
                else:
                    last_event = now
                    last_event_timestamp = int(now.timestamp())
                self.helper.log_info("Connector has never run")

            # If import with tags
            complex_query_tag = None
            if (self.misp_import_tags is not None) or (
                self.misp_import_tags_not is not None
            ):
                or_parameters = []
                not_parameters = []

                if self.misp_import_tags:
                    for tag in self.misp_import_tags.split(","):
                        or_parameters.append(tag.strip())
                if self.misp_import_tags_not:
                    for ntag in self.misp_import_tags_not.split(","):
                        not_parameters.append(ntag.strip())

                complex_query_tag = self.misp.build_complex_query(
                    or_parameters=or_parameters if len(or_parameters) > 0 else None,
                    not_parameters=not_parameters if len(not_parameters) > 0 else None,
                )

            # Prepare the query
            kwargs = dict()

            # Put the date
            next_event_timestamp = last_event_timestamp + 1
            kwargs[self.misp_filter_date_attribute] = next_event_timestamp

            # Complex query date
            if complex_query_tag is not None:
                kwargs["tags"] = complex_query_tag

            # With attachments
            if self.import_with_attachments:
                kwargs["with_attachments"] = self.import_with_attachments

            # Query with pagination of 50
            current_state = self.helper.get_state()
            if current_state is not None and "current_page" in current_state:
                current_page = current_state["current_page"]
            else:
                current_page = 1
            number_events = 0
            while True:
                kwargs["limit"] = 10
                kwargs["page"] = current_page
                if self.misp_import_keyword is not None:
                    kwargs["value"] = self.misp_import_keyword
                    kwargs["searchall"] = True
                if self.misp_enforce_warning_list is not None:
                    kwargs["enforce_warninglist"] = self.misp_enforce_warning_list
                self.helper.log_info(
                    "Fetching MISP events with args: " + json.dumps(kwargs)
                )
                kwargs = json.loads(json.dumps(kwargs))
                events = []
                try:
                    events = self.misp.search("events", **kwargs)
                    if isinstance(events, dict):
                        if "errors" in events:
                            raise ValueError(events["message"])
                except Exception as e:
                    self.helper.log_error(f"Error fetching misp event: {e}")
                    self.helper.metric.inc("client_error_count")
                    try:
                        events = self.misp.search("events", **kwargs)
                        if isinstance(events, dict):
                            if "errors" in events:
                                raise ValueError(events["message"])
                    except Exception as e:
                        self.helper.log_error(f"Error fetching misp event again: {e}")
                        self.helper.metric.inc("client_error_count")
                        break

                self.helper.log_info("MISP returned " + str(len(events)) + " events.")
                number_events = number_events + len(events)

                # Break if no more result
                if len(events) == 0:
                    break

                # Process the event
                processed_events_last_timestamp = self.process_events(work_id, events)
                if (
                    processed_events_last_timestamp is not None
                    and processed_events_last_timestamp > last_event_timestamp
                ):
                    last_event_timestamp = processed_events_last_timestamp

                # Next page
                current_page += 1
                if current_state is not None:
                    current_state["current_page"] = current_page
                else:
                    current_state = {"current_page": current_page}
                self.helper.set_state(current_state)
            # Loop is over, storing the state
            # We cannot store the state before, because MISP events are NOT ordered properly
            # and there is NO WAY to order them using their library
            message = (
                "Connector successfully run ("
                + str(number_events)
                + " events have been processed), storing state (last_run="
                + now.astimezone(pytz.utc).isoformat()
                + ", last_event="
                + datetime.utcfromtimestamp(last_event_timestamp)
                .astimezone(pytz.UTC)
                .isoformat()
                + ", last_event_timestamp="
                + str(last_event_timestamp)
                + ", current_page=1)"
            )
            self.helper.set_state(
                {
                    "last_run": now.astimezone(pytz.utc).isoformat(),
                    "last_event": datetime.utcfromtimestamp(last_event_timestamp)
                    .astimezone(pytz.UTC)
                    .isoformat(),
                    "last_event_timestamp": last_event_timestamp,
                    "current_page": 1,
                }
            )
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                self.helper.force_ping()
                sys.exit(0)

            self.helper.metric.state("idle")
            time.sleep(self.get_interval())

    def process_events(self, work_id, events):
        # Prepare filters
        import_creator_orgs = None
        import_creator_orgs_not = None
        import_owner_orgs = None
        import_owner_orgs_not = None
        import_distribution_levels = None
        import_threat_levels = None
        last_event_timestamp = None
        if self.misp_import_creator_orgs is not None:
            import_creator_orgs = self.misp_import_creator_orgs.split(",")
        if self.misp_import_creator_orgs_not is not None:
            import_creator_orgs_not = self.misp_import_creator_orgs_not.split(",")
        if self.misp_import_owner_orgs is not None:
            import_owner_orgs = self.misp_import_owner_orgs.split(",")
        if self.misp_import_owner_orgs_not is not None:
            import_owner_orgs_not = self.misp_import_owner_orgs_not.split(",")
        if self.import_distribution_levels is not None:
            import_distribution_levels = self.import_distribution_levels.split(",")
        if self.import_threat_levels is not None:
            import_threat_levels = self.import_threat_levels.split(",")

        for event in events:
            self.helper.log_info("Processing event " + event["Event"]["uuid"])
            event_timestamp = int(event["Event"][self.misp_datetime_attribute])
            # need to check if timestamp is more recent than the previous event since
            # events are not ordered by timestamp in API response
            if last_event_timestamp is None or event_timestamp > last_event_timestamp:
                last_event_timestamp = event_timestamp
            # Check against filter
            if (
                import_creator_orgs is not None
                and event["Event"]["Orgc"]["name"] not in import_creator_orgs
            ):
                self.helper.log_info(
                    "Event creator organization "
                    + event["Event"]["Orgc"]["name"]
                    + " not in import_creator_orgs, do not import"
                )
                continue
            if (
                import_creator_orgs_not is not None
                and event["Event"]["Orgc"]["name"] in import_creator_orgs_not
            ):
                self.helper.log_info(
                    "Event creator organization "
                    + event["Event"]["Orgc"]["name"]
                    + " in import_creator_orgs_not, do not import"
                )
                continue
            if (
                import_owner_orgs is not None
                and event["Event"]["Org"]["name"] not in import_owner_orgs
            ):
                self.helper.log_info(
                    "Event owner organization "
                    + event["Event"]["Org"]["name"]
                    + " not in import_owner_orgs, do not import"
                )
                continue
            if (
                import_owner_orgs_not is not None
                and event["Event"]["Org"]["name"] in import_owner_orgs_not
            ):
                self.helper.log_info(
                    "Event owner organization "
                    + event["Event"]["Org"]["name"]
                    + " in import_owner_orgs_not, do not import"
                )
                continue
            if (
                import_distribution_levels is not None
                and event["Event"]["distribution"] not in import_distribution_levels
            ):
                self.helper.log_info(
                    "Event distribution level "
                    + event["Event"]["distribution"]
                    + " not in import_distribution_levels, do not import"
                )
                continue
            if (
                import_threat_levels is not None
                and event["Event"]["threat_level_id"] not in import_threat_levels
            ):
                self.helper.log_info(
                    "Event threat level "
                    + event["Event"]["threat_level_id"]
                    + " not in import_threat_levels, do not import"
                )
                continue
            if (
                self.import_only_published is not None
                and self.import_only_published
                and not event["Event"]["published"]
            ):
                self.helper.log_info(
                    "Event is not published and import_only_published is set, do not import"
                )
                continue

            ### Default variables
            added_markings = []
            added_entities = []
            added_object_refs = []
            added_sightings = []
            added_files = []
            added_observables = []
            added_relationships = []

            ### Pre-process
            # Author
            author = None
            if self.misp_author_from_tags:
                if "Tag" in event["Event"]:
                    event_tags = event["Event"]["Tag"]
                    for tag in event_tags:
                        tag_name = tag["name"]
                        if tag_name.startswith("creator") and "=" in tag_name:
                            author_name = tag_name.split("=")[1]
                            author = stix2.Identity(
                                id=Identity.generate_id(author_name, "organization"),
                                name=author_name,
                                identity_class="organization",
                            )
            if author is None:
                author = stix2.Identity(
                    id=Identity.generate_id(
                        event["Event"]["Orgc"]["name"], "organization"
                    ),
                    name=event["Event"]["Orgc"]["name"],
                    identity_class="organization",
                )
            # Markings
            if "Tag" in event["Event"]:
                event_markings = self.resolve_markings(event["Event"]["Tag"])
            else:
                event_markings = [marking_tlp_clear]
            # Elements
            event_elements = self.prepare_elements(
                event["Event"].get("Galaxy", []),
                event["Event"].get("Tag", []),
                author,
                event_markings,
            )
            self.helper.log_info(
                "This event contains " + str(len(event_elements)) + " related elements"
            )
            # Tags
            event_tags = []
            if "Tag" in event["Event"]:
                event_tags = self.resolve_tags(event["Event"]["Tag"])
            # ExternalReference
            if self.misp_reference_url is not None and len(self.misp_reference_url) > 0:
                url = self.misp_reference_url + "/events/view/" + event["Event"]["uuid"]
            else:
                url = self.misp_url + "/events/view/" + event["Event"]["uuid"]
            event_external_reference = stix2.ExternalReference(
                source_name=self.helper.connect_name,
                description=event["Event"]["info"],
                external_id=event["Event"]["uuid"],
                url=url,
            )

            ### Get indicators
            event_external_references = [event_external_reference]
            indicators = []
            # Get attributes of event
            self.helper.log_info(
                "This event contains "
                + str(len(event["Event"]["Attribute"]))
                + " attributes..."
            )
            create_relationships = len(event["Event"]["Attribute"]) < 10000
            for attribute in event["Event"]["Attribute"]:
                indicator = self.process_attribute(
                    author,
                    event_elements,
                    event_markings,
                    event_tags,
                    None,
                    [],
                    attribute,
                    event["Event"]["threat_level_id"],
                    create_relationships,
                )
                if (
                    attribute["type"] == "link"
                    and attribute["category"] == "External analysis"
                ):
                    event_external_references.append(
                        stix2.ExternalReference(
                            source_name=attribute["category"],
                            external_id=attribute["uuid"],
                            url=attribute["value"],
                        )
                    )
                if indicator is not None:
                    indicators.append(indicator)

                pdf_file = self._get_pdf_file(attribute)
                if pdf_file is not None:
                    added_files.append(pdf_file)

            # Get attributes of objects
            indicators_relationships = []
            objects_relationships = []
            objects_observables = []
            event_threat_level = event["Event"]["threat_level_id"]
            for object in event["Event"].get("Object", []):
                attribute_external_references = []
                for attribute in object["Attribute"]:
                    if (
                        attribute["type"] == "link"
                        and attribute["category"] == "External analysis"
                    ):
                        attribute_external_references.append(
                            stix2.ExternalReference(
                                source_name=attribute["category"],
                                external_id=attribute["uuid"],
                                url=attribute["value"],
                            )
                        )

                    pdf_file = self._get_pdf_file(attribute)
                    if pdf_file is not None:
                        added_files.append(pdf_file)

                object_observable = None
                if self.misp_create_object_observables:
                    if self.import_unsupported_observables_as_text_transparent:
                        if len(object["Attribute"]) > 0:
                            value = object["Attribute"][0]["value"]
                            object_observable = CustomObservableText(
                                value=value,
                                object_marking_refs=event_markings,
                                custom_properties={
                                    "description": object["description"],
                                    "x_opencti_score": self.threat_level_to_score(
                                        event_threat_level
                                    ),
                                    "labels": event_tags,
                                    "created_by_ref": author["id"],
                                    "external_references": attribute_external_references,
                                },
                            )
                            objects_observables.append(object_observable)
                    else:
                        unique_key = ""
                        if len(object["Attribute"]) > 0:
                            unique_key = (
                                " ("
                                + object["Attribute"][0]["type"]
                                + "="
                                + object["Attribute"][0]["value"]
                                + ")"
                            )
                        object_observable = CustomObservableText(
                            value=object["name"] + unique_key,
                            object_marking_refs=event_markings,
                            custom_properties={
                                "description": object["description"],
                                "x_opencti_score": self.threat_level_to_score(
                                    event_threat_level
                                ),
                                "labels": event_tags,
                                "created_by_ref": author["id"],
                                "external_references": attribute_external_references,
                            },
                        )
                        objects_observables.append(object_observable)
                object_attributes = []
                create_relationships = len(object["Attribute"]) < 10000
                for attribute in object["Attribute"]:
                    indicator = self.process_attribute(
                        author,
                        event_elements,
                        event_markings,
                        event_tags,
                        object_observable,
                        attribute_external_references,
                        attribute,
                        event["Event"]["threat_level_id"],
                        create_relationships,
                    )
                    if indicator is not None:
                        indicators.append(indicator)
                        if (
                            indicator["indicator"] is not None
                            and object["meta-category"] == "file"
                            and indicator["indicator"].get(
                                "x_opencti_main_observable_type", "Unknown"
                            )
                            in FILETYPES
                        ):
                            object_attributes.append(indicator)
                # TODO Extend observable

            ### Prepare the bundle
            bundle_objects = [author]
            object_refs = []
            # Add event markings
            for event_marking in event_markings:
                if event_marking["id"] not in added_markings:
                    bundle_objects.append(event_marking)
                    added_markings.append(event_marking["id"])
            # Add event elements
            all_event_elements = (
                event_elements["intrusion_sets"]
                + event_elements["malwares"]
                + event_elements["tools"]
                + event_elements["attack_patterns"]
                + event_elements["sectors"]
                + event_elements["countries"]
                + event_elements["regions"]
            )
            for event_element in all_event_elements:
                if event_element["id"] not in added_object_refs:
                    object_refs.append(event_element)
                    added_object_refs.append(event_element["id"])
                if event_element["id"] not in added_entities:
                    bundle_objects.append(event_element)
                    added_entities.append(event_element["id"])
            # Add indicators
            for indicator in indicators:
                if indicator["indicator"] is not None:
                    if indicator["indicator"]["id"] not in added_object_refs:
                        object_refs.append(indicator["indicator"])
                        added_object_refs.append(indicator["indicator"]["id"])
                    if indicator["indicator"]["id"] not in added_entities:
                        bundle_objects.append(indicator["indicator"])
                        added_entities.append(indicator["indicator"]["id"])
                if indicator["observable"] is not None:
                    if indicator["observable"]["id"] not in added_object_refs:
                        object_refs.append(indicator["observable"])
                        added_object_refs.append(indicator["observable"]["id"])
                    if indicator["observable"]["id"] not in added_entities:
                        bundle_objects.append(indicator["observable"])
                        added_entities.append(indicator["observable"]["id"])

                # Add attribute markings
                for attribute_marking in indicator["markings"]:
                    if attribute_marking["id"] not in added_markings:
                        bundle_objects.append(attribute_marking)
                        added_markings.append(attribute_marking["id"])
                # Add attribute sightings identities
                for attribute_identity in indicator["identities"]:
                    if attribute_identity["id"] not in added_entities:
                        bundle_objects.append(attribute_identity)
                        added_entities.append(attribute_identity["id"])
                # Add attribute sightings
                for attribute_sighting in indicator["sightings"]:
                    if attribute_sighting["id"] not in added_sightings:
                        bundle_objects.append(attribute_sighting)
                        added_sightings.append(attribute_sighting["id"])
                # Add attribute elements
                all_attribute_elements = (
                    indicator["attribute_elements"]["intrusion_sets"]
                    + indicator["attribute_elements"]["malwares"]
                    + indicator["attribute_elements"]["tools"]
                    + indicator["attribute_elements"]["attack_patterns"]
                    + indicator["attribute_elements"]["sectors"]
                    + indicator["attribute_elements"]["countries"]
                    + indicator["attribute_elements"]["regions"]
                )
                for attribute_element in all_attribute_elements:
                    if attribute_element["id"] not in added_object_refs:
                        object_refs.append(attribute_element)
                        added_object_refs.append(attribute_element["id"])
                    if attribute_element["id"] not in added_entities:
                        bundle_objects.append(attribute_element)
                        added_entities.append(attribute_element["id"])
                # Add attribute relationships
                for relationship in indicator["relationships"]:
                    indicators_relationships.append(relationship)

            # We want to make sure these are added as lasts, so we're sure all the related objects are created
            for indicator_relationship in indicators_relationships:
                objects_relationships.append(indicator_relationship)
            # Add MISP objects_observables
            for object_observable in objects_observables:
                if object_observable["id"] not in added_object_refs:
                    object_refs.append(object_observable)
                    added_object_refs.append(object_observable["id"])
                if object_observable["id"] not in added_observables:
                    bundle_objects.append(object_observable)
                    added_observables.append(object_observable["id"])

            # Link all objects with each other, now so we can find the correct entity type prefix in bundle_objects
            for object in event["Event"].get("Object", []):
                for ref in object.get("ObjectReference", []):
                    ref_src = ref.get("source_uuid")
                    ref_target = ref.get("referenced_uuid")
                    if ref_src is not None and ref_target is not None:
                        src_result = self.find_type_by_uuid(ref_src, bundle_objects)
                        target_result = self.find_type_by_uuid(
                            ref_target, bundle_objects
                        )
                        if src_result is not None and target_result is not None:
                            objects_relationships.append(
                                stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to",
                                        src_result["entity"]["id"],
                                        target_result["entity"]["id"],
                                    ),
                                    relationship_type="related-to",
                                    created_by_ref=author["id"],
                                    description="Original Relationship: "
                                    + ref["relationship_type"]
                                    + "  \nComment: "
                                    + ref["comment"],
                                    source_ref=src_result["entity"]["id"],
                                    target_ref=target_result["entity"]["id"],
                                    allow_custom=True,
                                )
                            )
            # Add object_relationships
            for object_relationship in objects_relationships:
                if (
                    object_relationship["source_ref"]
                    + object_relationship["target_ref"]
                    not in added_object_refs
                ):
                    object_refs.append(object_relationship)
                    added_object_refs.append(
                        object_relationship["source_ref"]
                        + object_relationship["target_ref"]
                    )
                if (
                    object_relationship["source_ref"]
                    + object_relationship["target_ref"]
                    not in added_relationships
                ):
                    bundle_objects.append(object_relationship)
                    added_relationships.append(
                        object_relationship["source_ref"]
                        + object_relationship["target_ref"]
                    )

            # Create the report if needed
            if self.misp_create_reports:
                # Report in STIX lib must have at least one object_refs
                if len(object_refs) == 0:
                    # Put a fake ID in the report
                    object_refs.append(
                        "intrusion-set--fc5ee88d-7987-4c00-991e-a863e9aa8a0e"
                    )
                attributes = filter_event_attributes(
                    event, **self.misp_report_description_attribute_filter
                )
                description = (
                    attributes[0]["value"] if attributes else event["Event"]["info"]
                )
                report = stix2.Report(
                    id=Report.generate_id(
                        event["Event"]["info"],
                        datetime.utcfromtimestamp(
                            int(
                                datetime.strptime(
                                    str(event["Event"]["date"]), "%Y-%m-%d"
                                ).timestamp()
                            )
                        ),
                    ),
                    name=event["Event"]["info"],
                    description=description,
                    published=datetime.utcfromtimestamp(
                        int(
                            datetime.strptime(
                                str(event["Event"]["date"]), "%Y-%m-%d"
                            ).timestamp()
                        )
                    ),
                    created=datetime.utcfromtimestamp(
                        int(
                            datetime.strptime(
                                str(event["Event"]["date"]), "%Y-%m-%d"
                            ).timestamp()
                        )
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=datetime.utcfromtimestamp(
                        int(event["Event"]["timestamp"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    report_types=[self.misp_report_type],
                    created_by_ref=author["id"],
                    object_marking_refs=event_markings,
                    labels=event_tags,
                    object_refs=object_refs,
                    external_references=event_external_references,
                    confidence=self.helper.connect_confidence_level,
                    custom_properties={
                        "x_opencti_files": added_files,
                    },
                    allow_custom=True,
                )
                bundle_objects.append(report)
                for note in event["Event"].get("EventReport", []):
                    note = stix2.Note(
                        id=Note.generate_id(
                            datetime.utcfromtimestamp(int(note["timestamp"])).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            self.process_note(note["content"], bundle_objects),
                        ),
                        confidence=self.helper.connect_confidence_level,
                        created=datetime.utcfromtimestamp(
                            int(note["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        modified=datetime.utcfromtimestamp(
                            int(note["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        created_by_ref=author["id"],
                        object_marking_refs=event_markings,
                        abstract=note["name"],
                        content=self.process_note(note["content"], bundle_objects),
                        object_refs=[report],
                        allow_custom=True,
                    )
                    bundle_objects.append(note)
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            self.helper.log_info("Sending event STIX2 bundle")

            self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.metric.inc("record_send", len(bundle_objects))
        return last_event_timestamp

    def _get_pdf_file(self, attribute):
        if not self.import_with_attachments:
            return None

        attr_type = attribute["type"]
        attr_category = attribute["category"]
        if not (attr_type == "attachment" and attr_category == "External analysis"):
            return None

        attr_value = attribute["value"]
        if not attr_value.endswith((".pdf", ".PDF")):
            return None

        attr_uuid = attribute["uuid"]

        attr_data = attribute.get("data")
        if attr_data is None:
            self.helper.log_error(
                "No data for attribute: {0} ({1}:{2})".format(
                    attr_uuid, attr_type, attr_category
                )
            )
            return None

        self.helper.log_info(
            "Found PDF '{0}' for attribute: {1} ({2}:{3})".format(
                attr_value, attr_uuid, attr_type, attr_category
            )
        )

        return {
            "name": attr_value,
            "data": attr_data,
            "mime_type": "application/pdf",
            "no_trigger_import": True,
        }

    def process_attribute(
        self,
        author: stix2.Identity,
        event_elements,
        event_markings,
        event_labels,
        object_observable,
        attribute_external_references,
        attribute,
        event_threat_level,
        create_relationships,
    ):
        if attribute["type"] == "link" and attribute["category"] == "External analysis":
            return None
        if attribute["type"] == "attachment":
            return None
        resolved_attributes = self.resolve_type(attribute["type"], attribute["value"])
        if resolved_attributes is None:
            return None
        file_name = None
        for resolved_attribute in resolved_attributes:
            if resolved_attribute["resolver"] == "file-name":
                file_name = resolved_attribute["value"]

        for resolved_attribute in resolved_attributes:
            ### Pre-process
            # Markings & Tags
            attribute_tags = event_labels
            if "Tag" in attribute:
                attribute_markings = self.resolve_markings(
                    attribute["Tag"], with_default=False
                )
                attribute_tags = self.resolve_tags(attribute["Tag"])
                if len(attribute_markings) == 0:
                    attribute_markings = event_markings
            else:
                attribute_markings = event_markings

            # Elements
            attribute_elements = self.prepare_elements(
                attribute.get("Galaxy", []),
                attribute.get("Tag", []),
                author,
                attribute_markings,
            )

            ### Create the indicator
            observable_resolver = resolved_attribute["resolver"]
            observable_type = resolved_attribute["type"]
            observable_value = resolved_attribute["value"]
            name = (
                resolved_attribute["value"]
                if len(resolved_attribute["value"]) > 2
                else (
                    attribute["comment"]
                    if len(attribute["comment"]) > 2
                    else observable_type
                )
            )
            pattern_type = "stix"
            pattern = None
            # observable type is yara or sigma for instance
            if observable_resolver in PATTERNTYPES:
                pattern_type = observable_resolver
                pattern = observable_value
                name = (
                    attribute["comment"]
                    if len(attribute["comment"]) > 2
                    else observable_type
                )
            # observable type is not in stix 2
            elif observable_resolver not in OPENCTISTIX2:
                return None
            # observable type is in stix
            elif "path" in OPENCTISTIX2[observable_resolver]:
                if "transform" in OPENCTISTIX2[observable_resolver]:
                    if (
                        OPENCTISTIX2[observable_resolver]["transform"]["operation"]
                        == "remove_string"
                    ):
                        observable_value = observable_value.replace(
                            OPENCTISTIX2[observable_resolver]["transform"]["value"],
                            "",
                        )
                lhs = stix2.ObjectPath(
                    OPENCTISTIX2[observable_resolver]["type"],
                    OPENCTISTIX2[observable_resolver]["path"],
                )
                genuine_pattern = str(
                    stix2.ObservationExpression(
                        stix2.EqualityComparisonExpression(lhs, observable_value)
                    )
                )
                pattern = genuine_pattern

            to_ids = attribute["to_ids"]

            score = self.threat_level_to_score(event_threat_level)
            if self.import_to_ids_no_score is not None and not to_ids:
                score = self.import_to_ids_no_score

            indicator = None
            if self.misp_create_indicators and pattern is not None:
                try:
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=name,
                        description=attribute["comment"],
                        confidence=self.helper.connect_confidence_level,
                        pattern_type=pattern_type,
                        pattern=pattern,
                        valid_from=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        labels=attribute_tags,
                        created_by_ref=author["id"],
                        object_marking_refs=attribute_markings,
                        external_references=attribute_external_references,
                        created=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        modified=datetime.utcfromtimestamp(
                            int(attribute["timestamp"])
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        custom_properties={
                            "x_opencti_main_observable_type": observable_type,
                            "x_opencti_detection": to_ids,
                            "x_opencti_score": score,
                        },
                        allow_custom=True,
                    )
                except Exception as e:
                    self.helper.log_error(f"Error processing indicator {name}: {e}")
                    self.helper.metric.inc("error_count")
            observable = None
            if self.misp_create_observables and observable_type is not None:
                try:
                    custom_properties = {
                        "x_opencti_description": attribute["comment"],
                        "x_opencti_score": score,
                        "labels": attribute_tags,
                        "created_by_ref": author["id"],
                        "external_references": attribute_external_references,
                    }
                    observable = None
                    if observable_type == "Autonomous-System":
                        observable = stix2.AutonomousSystem(
                            number=observable_value.replace("AS", ""),
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mac-Addr":
                        observable = stix2.MACAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Hostname":
                        observable = CustomObservableHostname(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Domain-Name":
                        observable = stix2.DomainName(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv4-Addr":
                        observable = stix2.IPv4Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "IPv6-Addr":
                        observable = stix2.IPv6Address(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Url":
                        observable = stix2.URL(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Addr":
                        observable = stix2.EmailAddress(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Email-Message":
                        observable = stix2.EmailMessage(
                            subject=observable_value,
                            is_multipart=True,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Mutex":
                        observable = stix2.Mutex(
                            name=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "User-Account":
                        if "account_type" in OPENCTISTIX2[observable_resolver]:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                account_type=OPENCTISTIX2[observable_resolver][
                                    "account_type"
                                ],
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        else:
                            observable = stix2.UserAccount(
                                account_login=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "File":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "name":
                            observable = stix2.File(
                                name=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif OPENCTISTIX2[observable_resolver]["path"][0] == "hashes":
                            hashes = {}
                            hashes[OPENCTISTIX2[observable_resolver]["path"][1]] = (
                                observable_value
                            )
                            observable = stix2.File(
                                name=file_name,
                                hashes=hashes,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Directory":
                        observable = stix2.Directory(
                            path=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Key":
                        observable = stix2.WindowsRegistryKey(
                            key=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Windows-Registry-Value-Type":
                        observable = stix2.WindowsRegistryValueType(
                            data=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "X509-Certificate":
                        if OPENCTISTIX2[observable_resolver]["path"][0] == "issuer":
                            observable = stix2.File(
                                issuer=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                        elif (
                            OPENCTISTIX2[observable_resolver]["path"][1]
                            == "serial_number"
                        ):
                            observable = stix2.File(
                                serial_number=observable_value,
                                object_marking_refs=attribute_markings,
                                custom_properties=custom_properties,
                            )
                    elif observable_type == "Phone-Number":
                        observable = CustomObservablePhoneNumber(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Text":
                        observable = CustomObservableText(
                            value=observable_value,
                            object_marking_refs=attribute_markings,
                            custom_properties=custom_properties,
                        )
                    elif observable_type == "Identity":
                        observable = stix2.Identity(
                            id=Identity.generate_id(
                                observable_value,
                                OPENCTISTIX2[observable_resolver]["identity_class"],
                            ),
                            name=observable_value,
                            identity_class=OPENCTISTIX2[observable_resolver][
                                "identity_class"
                            ],
                            description=attribute["comment"],
                            labels=attribute_tags,
                            created_by_ref=author["id"],
                            external_references=attribute_external_references,
                        )
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating observable type {observable_type} with value {observable_value}: {e}"
                    )
                    self.helper.metric.inc("error_count")
            sightings = []
            identities = []
            if "Sighting" in attribute:
                for misp_sighting in attribute["Sighting"]:
                    if (
                        "Organisation" in misp_sighting
                        and misp_sighting["Organisation"]["name"] != author.name
                    ):
                        sighted_by = stix2.Identity(
                            id=Identity.generate_id(
                                misp_sighting["Organisation"]["name"], "organization"
                            ),
                            name=misp_sighting["Organisation"]["name"],
                            identity_class="organization",
                        )
                        identities.append(sighted_by)
                    else:
                        sighted_by = None

                    if indicator is not None and sighted_by is not None:
                        sighting = stix2.Sighting(
                            id=StixSightingRelationship.generate_id(
                                indicator["id"],
                                sighted_by["id"],
                                datetime.utcfromtimestamp(
                                    int(misp_sighting["date_sighting"])
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                datetime.utcfromtimestamp(
                                    int(misp_sighting["date_sighting"]) + 3600
                                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            ),
                            sighting_of_ref=indicator["id"],
                            first_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"])
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            last_seen=datetime.utcfromtimestamp(
                                int(misp_sighting["date_sighting"]) + 3600
                            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            where_sighted_refs=(
                                [sighted_by] if sighted_by is not None else None
                            ),
                        )
                        sightings.append(sighting)
                    # if observable is not None:
                    #     sighting = Sighting(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id("sighting"),
                    #         sighting_of_ref=observable["id"],
                    #         first_seen=datetime.utcfromtimestamp(
                    #             int(misp_sighting["date_sighting"])
                    #         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    #         last_seen=datetime.utcfromtimestamp(
                    #             int(misp_sighting["date_sighting"])
                    #         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    #         where_sighted_refs=[sighted_by]
                    #         if sighted_by is not None
                    #         else None,
                    #     )
                    #     sightings.append(sighting)

            ### Create the relationships
            relationships = []
            if not create_relationships:
                return {
                    "indicator": indicator,
                    "observable": observable,
                    "relationships": relationships,
                    "attribute_elements": attribute_elements,
                    "markings": attribute_markings,
                    "identities": identities,
                    "sightings": sightings,
                }
            if indicator is not None and observable is not None:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", indicator.id, observable.id
                        ),
                        relationship_type="based-on",
                        created_by_ref=author["id"],
                        source_ref=indicator.id,
                        target_ref=observable.id,
                        allow_custom=True,
                    )
                )

            # Create relationship between MISP attribute (indicator or observable) and MISP object (observable)
            if object_observable is not None:

                indicator_id = indicator.get("id") if indicator else None
                observable_id = observable.get("id") if observable else None
                source_id = object_observable.get("id")
                target_id = (
                    observable_id
                    if observable_id is not None and observable_id != source_id
                    else indicator_id
                )

                if target_id is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                source_id,
                                target_id,
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=source_id,
                            target_ref=target_id,
                            allow_custom=True,
                        )
                    )

            # Event threats
            threat_names = {}
            for threat in (
                event_elements["intrusion_sets"]
                + event_elements["malwares"]
                + event_elements["tools"]
            ):
                threat_names[threat.name] = threat.id
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "indicates", indicator.id, threat.id
                            ),
                            relationship_type="indicates",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, threat.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=threat.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )

            # Attribute threats
            for threat in (
                attribute_elements["intrusion_sets"]
                + attribute_elements["malwares"]
                + attribute_elements["tools"]
            ):
                if threat.name in threat_names:
                    threat_id = threat_names[threat.name]
                else:
                    threat_id = threat.id
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "indicates", indicator.id, threat_id
                            ),
                            relationship_type="indicates",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=threat_id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, threat_id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=threat_id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
            # Event Attack Patterns
            for attack_pattern in event_elements["attack_patterns"]:
                if len(event_elements["malwares"]) > 0:
                    threats = event_elements["malwares"]
                elif len(event_elements["intrusion_sets"]) > 0:
                    threats = event_elements["intrusion_sets"]
                else:
                    threats = []
                for threat in threats:
                    if threat.name in threat_names:
                        threat_id = threat_names[threat.name]
                    else:
                        threat_id = threat.id
                    relationship_uses = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", threat_id, attack_pattern.id
                        ),
                        relationship_type="uses",
                        created_by_ref=author["id"],
                        source_ref=threat_id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                    relationships.append(relationship_uses)
                    # if indicator is not None:
                    #     relationship_indicates = Relationship(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id(
                    #             "relationship"
                    #         ),
                    #         relationship_type="indicates",
                    #         created_by_ref=author["id"],
                    #         source_ref=indicator.id,
                    #         target_ref=relationship_uses.id,
                    #         description=attribute["comment"],
                    #         confidence=self.helper.connect_confidence_level,
                    #         object_marking_refs=attribute_markings,
                    #     )
                    #     relationships.append(relationship_indicates)
                    # if observable is not None:
                    #     relationship_indicates = Relationship(
                    #         id=OpenCTIStix2Utils.generate_random_stix_id(
                    #             "relationship"
                    #         ),
                    #         relationship_type="related-to",
                    #         created_by_ref=author["id"],
                    #         source_ref=observable.id,
                    #         target_ref=relationship_uses.id,
                    #         description=attribute["comment"],
                    #         confidence=self.helper.connect_confidence_level,
                    #         object_marking_refs=attribute_markings,
                    #     )
                    #     relationships.append(relationship_indicates)

            # Attribute Attack Patterns
            for attack_pattern in attribute_elements["attack_patterns"]:
                if len(attribute_elements["malwares"]) > 0:
                    threats = attribute_elements["malwares"]
                elif len(attribute_elements["intrusion_sets"]) > 0:
                    threats = attribute_elements["intrusion_sets"]
                else:
                    threats = []
                for threat in threats:
                    if threat.name in threat_names:
                        threat_id = threat_names[threat.name]
                    else:
                        threat_id = threat.id
                    relationship_uses = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", threat_id, attack_pattern.id
                        ),
                        relationship_type="uses",
                        confidence=self.helper.connect_confidence_level,
                        created_by_ref=author["id"],
                        source_ref=threat_id,
                        target_ref=attack_pattern.id,
                        description=attribute["comment"],
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                    relationships.append(relationship_uses)
                    # if indicator is not None:
                    #    relationship_indicates = Relationship(
                    #        id=OpenCTIStix2Utils.generate_random_stix_id(
                    #            "relationship"
                    #        ),
                    #        relationship_type="indicates",
                    #        created_by_ref=author["id"],
                    #        source_ref=indicator.id,
                    #        target_ref=relationship_uses.id,
                    #        description=attribute["comment"],
                    #        confidence=self.helper.connect_confidence_level,
                    #        object_marking_refs=attribute_markings,
                    #    )
                    #    relationships.append(relationship_indicates)
                    # if observable is not None:
                    #    relationship_indicates = Relationship(
                    #        id=OpenCTIStix2Utils.generate_random_stix_id(
                    #            "relationship"
                    #        ),
                    #        relationship_type="indicates",
                    #        created_by_ref=author["id"],
                    #        source_ref=observable.id,
                    #        target_ref=relationship_uses.id,
                    #        description=attribute["comment"],
                    #        confidence=self.helper.connect_confidence_level,
                    #        object_marking_refs=attribute_markings,
                    #    )
                    #    relationships.append(relationship_indicates)
            for sector in attribute_elements["sectors"]:
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", indicator.id, sector.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=sector.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, sector.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=sector.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )

            for country in attribute_elements["countries"]:
                if indicator is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", indicator.id, country.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=country.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
                if observable is not None:
                    relationships.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", observable.id, country.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable.id,
                            target_ref=country.id,
                            description=attribute["comment"],
                            object_marking_refs=attribute_markings,
                            confidence=self.helper.connect_confidence_level,
                            allow_custom=True,
                        )
                    )
            return {
                "indicator": indicator,
                "observable": observable,
                "relationships": relationships,
                "attribute_elements": attribute_elements,
                "markings": attribute_markings,
                "identities": identities,
                "sightings": sightings,
            }

    def prepare_elements(self, galaxies, tags, author, markings):
        elements = {
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "sectors": [],
            "countries": [],
            "regions": [],
        }
        added_names = []
        for galaxy in galaxies:
            # Get the linked intrusion sets
            if (
                (
                    galaxy["namespace"] == "mitre-attack"
                    and galaxy["name"] == "Intrusion Set"
                )
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Threat Actor")
                or (
                    galaxy["namespace"] == "misp"
                    and galaxy["name"] == "Microsoft Activity Group actor"
                )
                or (
                    galaxy["namespace"] == "misp"
                    and galaxy["name"] == "ESET Threat Actor"
                )
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - G" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - G")[0]
                    elif "APT " in galaxy_entity["value"]:
                        name = galaxy_entity["value"].replace("APT ", "APT")
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names and not is_uuid(name):
                        elements["intrusion_sets"].append(
                            stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                labels=["intrusion-set"],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={"x_opencti_aliases": aliases},
                            )
                        )
                        added_names.append(name)
            # Get the linked tools
            if galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Tool":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["tools"].append(
                            stix2.Tool(
                                id=Tool.generate_id(name),
                                name=name,
                                labels=["tool"],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={"x_opencti_aliases": aliases},
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked malwares
            if (
                (galaxy["namespace"] == "mitre-attack" and galaxy["name"] == "Malware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Tool")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Ransomware")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Android")
                or (galaxy["namespace"] == "misp" and galaxy["name"] == "Malpedia")
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - S" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - S")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        elements["malwares"].append(
                            stix2.Malware(
                                id=Malware.generate_id(name),
                                name=name,
                                is_family=True,
                                confidence=self.helper.connect_confidence_level,
                                aliases=aliases,
                                labels=[galaxy["name"]],
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked attack_patterns
            if (
                galaxy["namespace"] == "mitre-attack"
                and galaxy["name"] == "Attack Pattern"
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    if " - T" in galaxy_entity["value"]:
                        name = galaxy_entity["value"].split(" - T")[0]
                    else:
                        name = galaxy_entity["value"]
                    if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
                        aliases = galaxy_entity["meta"]["synonyms"]
                    else:
                        aliases = [name]
                    if name not in added_names:
                        x_mitre_id = None
                        if "external_id" in galaxy_entity["meta"]:
                            if len(galaxy_entity["meta"]["external_id"]) > 0:
                                x_mitre_id = galaxy_entity["meta"]["external_id"][0]
                        elements["attack_patterns"].append(
                            stix2.AttackPattern(
                                id=AttackPattern.generate_id(name, x_mitre_id),
                                name=name,
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                custom_properties={
                                    "x_mitre_id": x_mitre_id,
                                    "x_opencti_aliases": aliases,
                                },
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked sectors
            if galaxy["namespace"] == "misp" and galaxy["name"] == "Sector":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    name = galaxy_entity["value"]
                    if name not in added_names:
                        elements["sectors"].append(
                            stix2.Identity(
                                id=Identity.generate_id(name, "class"),
                                name=name,
                                identity_class="class",
                                description=galaxy_entity["description"],
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)

            # Get the linked countries
            if galaxy["namespace"] == "misp" and galaxy["name"] == "Country":
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    name = galaxy_entity["description"]
                    if name not in added_names:
                        elements["countries"].append(
                            stix2.Location(
                                id=Location.generate_id(name, "Country"),
                                name=name,
                                country=galaxy_entity["meta"]["ISO"],
                                description="Imported from MISP tag",
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)

            # Get the linked regions
            if (
                galaxy["namespace"] == "misp"
                and galaxy["type"] == "region"
                and galaxy["name"] == "Regions UN M49"
            ):
                for galaxy_entity in galaxy["GalaxyCluster"]:
                    name = galaxy_entity["value"].split(" - ")[1]
                    if name not in added_names:
                        elements["regions"].append(
                            stix2.Location(
                                id=Location.generate_id(name, "Region"),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                region=name,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)

        for tag in tags:
            # Try to guess from tags
            if self.misp_guess_threats_from_tags:
                tag_value_split = tag["name"].split("=")
                if len(tag_value_split) == 1:
                    tag_value = tag_value_split[0]
                else:
                    tag_value = tag_value_split[1].replace('"', "")
                tag_value_split = tag_value.split(":")
                if len(tag_value_split) == 1:
                    tag_value = tag_value_split[0]
                else:
                    tag_value = tag_value_split[1].replace('"', "")
                if len(tag_value) > 0:
                    threats = self.helper.api.stix_domain_object.list(
                        types=["Intrusion-Set", "Malware", "Tool", "Attack-Pattern"],
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": [
                                        "name",
                                        "x_mitre_id",
                                        "aliases",
                                        "x_opencti_aliases",
                                    ],
                                    "values": [tag_value],
                                }
                            ],
                            "filterGroups": [],
                        },
                    )
                    if len(threats) > 0:
                        threat = threats[0]
                        if threat["name"] not in added_names and not is_uuid(
                            threat["name"]
                        ):
                            if threat["entity_type"] == "Intrusion-Set":
                                elements["intrusion_sets"].append(
                                    stix2.IntrusionSet(
                                        id=IntrusionSet.generate_id(threat["name"]),
                                        name=threat["name"],
                                        confidence=self.helper.connect_confidence_level,
                                        created_by_ref=author["id"],
                                        object_marking_refs=markings,
                                        allow_custom=True,
                                    )
                                )
                                added_names.append(threat["name"])
                            if threat["entity_type"] == "Malware":
                                elements["malwares"].append(
                                    stix2.Malware(
                                        id=Malware.generate_id(threat["name"]),
                                        name=threat["name"],
                                        is_family=True,
                                        confidence=self.helper.connect_confidence_level,
                                        created_by_ref=author["id"],
                                        object_marking_refs=markings,
                                        allow_custom=True,
                                    )
                                )
                                added_names.append(threat["name"])
                            if threat["entity_type"] == "Tool":
                                elements["tools"].append(
                                    stix2.Tool(
                                        id=Tool.generate_id(threat["name"]),
                                        name=threat["name"],
                                        confidence=self.helper.connect_confidence_level,
                                        created_by_ref=author["id"],
                                        object_marking_refs=markings,
                                        allow_custom=True,
                                    )
                                )
                                added_names.append(threat["name"])
                            if threat["entity_type"] == "Attack-Pattern":
                                elements["attack_patterns"].append(
                                    stix2.AttackPattern(
                                        id=AttackPattern.generate_id(threat["name"]),
                                        name=threat["name"],
                                        confidence=self.helper.connect_confidence_level,
                                        created_by_ref=author["id"],
                                        object_marking_refs=markings,
                                        allow_custom=True,
                                    )
                                )
                                added_names.append(threat["name"])
            # Get the linked intrusion sets
            if (
                tag["name"].startswith("misp-galaxy:threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                or tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                or tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                or tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                or tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
                or tag["name"].startswith("intrusion-set")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - G" in tag_value:
                        name = tag_value.split(" - G")[0]
                    elif "APT " in tag_value:
                        name = tag_value.replace("APT ", "APT")
                    else:
                        name = tag_value
                    if name not in added_names and not is_uuid(name):
                        elements["intrusion_sets"].append(
                            stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked tools
            if (
                tag["name"].startswith("misp-galaxy:mitre-tool")
                or tag["name"].startswith("misp-galaxy:mitre-enterprise-attack-tool")
                or tag["name"].startswith("tool")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - S" in tag_value:
                        name = tag_value.split(" - S")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["tools"].append(
                            stix2.Tool(
                                id=Tool.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked malwares
            if (
                tag["name"].startswith("misp-galaxy:mitre-malware")
                or tag["name"].startswith("misp-galaxy:mitre-enterprise-attack-malware")
                or tag["name"].startswith("misp-galaxy:misp-ransomware")
                or tag["name"].startswith("misp-galaxy:misp-tool")
                or tag["name"].startswith("misp-galaxy:misp-android")
                or tag["name"].startswith("misp-galaxy:misp-malpedia")
                or tag["name"].startswith("malware")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - S" in tag_value:
                        name = tag_value.split(" - S")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["malwares"].append(
                            stix2.Malware(
                                id=Malware.generate_id(name),
                                name=name,
                                is_family=True,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked attack_patterns
            if (
                tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                or tag["name"].startswith("misp-galaxy:attack-pattern")
                or tag["name"].startswith("mitre-attack:attack-pattern")
                or tag["name"].startswith("mitre:")
            ):
                if "=" in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                else:
                    tag_value_split = tag["name"].split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    if "=" in tag["name"]:
                        tag_value = tag_value_split[1][:-1].strip()
                    else:
                        tag_value = tag_value_split[1].strip()
                    if " - T" in tag_value:
                        name = tag_value.split(" - T")[0]
                    else:
                        name = tag_value
                    if name not in added_names:
                        elements["attack_patterns"].append(
                            stix2.AttackPattern(
                                id=AttackPattern.generate_id(name),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
            # Get the linked sectors
            if tag["name"].startswith("misp-galaxy:sector"):
                tag_value_split = tag["name"].split('="')
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    name = tag_value_split[1][:-1].strip()
                    if name not in added_names:
                        elements["sectors"].append(
                            stix2.Identity(
                                id=Identity.generate_id(name, "class"),
                                name=name,
                                confidence=self.helper.connect_confidence_level,
                                identity_class="class",
                                created_by_ref=author["id"],
                                object_marking_refs=markings,
                                allow_custom=True,
                            )
                        )
                        added_names.append(name)
        return elements

    def resolve_type(self, type, value):
        types = {
            "yara": [{"resolver": "yara"}],
            "sigma": [{"resolver": "sigma"}],
            "snort": [{"resolver": "snort"}],
            "suricata": [{"resolver": "suricata"}],
            "md5": [{"resolver": "file-md5", "type": "File"}],
            "sha1": [{"resolver": "file-sha1", "type": "File"}],
            "sha256": [{"resolver": "file-sha256", "type": "File"}],
            "filename": [{"resolver": "file-name", "type": "File"}],
            "pdb": [{"resolver": "pdb-path", "type": "File"}],
            "filename|md5": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-md5", "type": "File"},
            ],
            "filename|sha1": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha1", "type": "File"},
            ],
            "filename|sha256": [
                {"resolver": "file-name", "type": "File"},
                {"resolver": "file-sha256", "type": "File"},
            ],
            "ip-src": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "ip-dst": [{"resolver": "ipv4-addr", "type": "IPv4-Addr"}],
            "ip-src|port": [
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
                {"resolver": "text", "type": "Text"},
            ],
            "ip-dst|port": [
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
                {"resolver": "text", "type": "Text"},
            ],
            "hostname": [{"resolver": "hostname", "type": "Hostname"}],
            "hostname|port": [
                {"resolver": "hostname", "type": "Hostname"},
                {"resolver": "text", "type": "Text"},
            ],
            "domain": [{"resolver": "domain", "type": "Domain-Name"}],
            "domain|ip": [
                {"resolver": "domain", "type": "Domain-Name"},
                {"resolver": "ipv4-addr", "type": "IPv4-Addr"},
            ],
            "email-subject": [{"resolver": "email-subject", "type": "Email-Message"}],
            "email": [{"resolver": "email-address", "type": "Email-Addr"}],
            "email-src": [{"resolver": "email-address", "type": "Email-Addr"}],
            "email-dst": [{"resolver": "email-address", "type": "Email-Addr"}],
            "url": [{"resolver": "url", "type": "Url"}],
            "windows-scheduled-task": [
                {"resolver": "windows-scheduled-task", "type": "Text"}
            ],
            "regkey": [{"resolver": "registry-key", "type": "Windows-Registry-Key"}],
            "user-agent": [{"resolver": "user-agent", "type": "User-Agent"}],
            "phone-number": [{"resolver": "phone-number", "type": "Phone-Number"}],
            "whois-registrant-email": [
                {"resolver": "email-address", "type": "Email-Addr"}
            ],
            "text": [{"resolver": "text", "type": "Text"}],
            "github-username": [
                {"resolver": "user-account-github", "type": "User-Account"}
            ],
            "full-name": [{"resolver": "identity-individual", "type": "Identity"}],
        }
        if type in types:
            resolved_types = types[type]
            if len(resolved_types) == 2:
                values = value.split("|")
                if len(values) == 2:
                    if resolved_types[0]["resolver"] == "ipv4-addr":
                        resolver_0 = self.detect_ip_version(values[0])
                        type_0 = self.detect_ip_version(values[0], True)
                    else:
                        resolver_0 = resolved_types[0]["resolver"]
                        type_0 = resolved_types[0]["type"]
                    if resolved_types[1]["resolver"] == "ipv4-addr":
                        resolver_1 = self.detect_ip_version(values[1])
                        type_1 = self.detect_ip_version(values[1], True)
                    else:
                        resolver_1 = resolved_types[1]["resolver"]
                        type_1 = resolved_types[1]["type"]
                    return [
                        {"resolver": resolver_0, "type": type_0, "value": values[0]},
                        {"resolver": resolver_1, "type": type_1, "value": values[1]},
                    ]
                else:
                    return None
            else:
                if (
                    "resolver" in resolved_types[0]
                    and resolved_types[0]["resolver"] == "ipv4-addr"
                    or resolved_types[0] == "ipv4-addr"
                ):
                    resolver_0 = self.detect_ip_version(value)
                    type_0 = self.detect_ip_version(value, True)
                else:
                    resolver_0 = resolved_types[0]["resolver"]
                    type_0 = (
                        resolved_types[0]["type"]
                        if "type" in resolved_types[0]
                        else None
                    )
                return [{"resolver": resolver_0, "type": type_0, "value": value}]
        # If not found, return text observable as a fallback
        if self.import_unsupported_observables_as_text:
            return [
                {
                    "resolver": "text",
                    "type": "Text",
                    "value": value + " (type=" + type + ")",
                }
            ]
        else:
            return None

    def detect_ip_version(self, value, type=False):
        if re.match(
            r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/([1-9]|[1-2]\d|3[0-2]))?$",
            value,
        ):
            if type:
                return "IPv4-Addr"
            return "ipv4-addr"
        else:
            if type:
                return "IPv6-Addr"
            return "ipv6-addr"

    def resolve_markings(self, tags, with_default=True):
        markings = []
        for tag in tags:
            tag_name = tag["name"]
            tag_name_lower = tag["name"].lower()
            if self.misp_markings_from_tags:
                if (
                    ":" in tag_name
                    and "=" in tag_name
                    and tag_name_lower.startswith("marking")
                ):
                    marking_definition_split = tag_name.split(":")
                    # Check if second part also contains ":"
                    if len(marking_definition_split) > 2:
                        # Example: marking:PAP=PAP:RED
                        # "PAP=PAP" + "RED"
                        marking_definition = (
                            marking_definition_split[1]
                            + ":"
                            + marking_definition_split[2]
                        )
                    else:
                        # Example: marking:CLASSIFICATION=DIFFUSION RESTREINTE
                        # CLASSIFICATION=DIFFUSION RESTREINTE
                        marking_definition = marking_definition_split[1]

                    # Split on the equal
                    marking_definition_split2 = marking_definition.split("=")

                    # PAP
                    # CLASSIFICATION
                    marking_type = marking_definition_split2[0]

                    # PAP:RED
                    # DIFFUSION RESTREINTE
                    marking_name = marking_definition_split2[1]

                    marking = stix2.MarkingDefinition(
                        id=MarkingDefinition.generate_id(marking_type, marking_name),
                        definition_type="statement",
                        definition={"statement": "custom"},
                        allow_custom=True,
                        x_opencti_definition_type=marking_type,
                        x_opencti_definition=marking_name,
                    )
                    markings.append(marking)
            if tag_name_lower == "tlp:clear":
                markings.append(marking_tlp_clear)
            if tag_name_lower == "tlp:white":
                markings.append(marking_tlp_clear)
            if tag_name_lower == "tlp:green":
                markings.append(stix2.TLP_GREEN)
            if tag_name_lower == "tlp:amber":
                markings.append(stix2.TLP_AMBER)
            if tag_name_lower == "tlp:amber+strict":
                marking = stix2.MarkingDefinition(
                    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "custom"},
                    allow_custom=True,
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                )
                markings.append(marking)
            if tag_name_lower == "tlp:red":
                markings.append(stix2.TLP_RED)
            # handle PAP markings
            if tag_name_lower == "pap:clear":
                markings.append(marking_pap_clear)
            if tag_name_lower == "pap:green":
                markings.append(marking_pap_green)
            if tag_name_lower == "pap:amber":
                markings.append(marking_pap_amber)
            if tag_name_lower == "pap:red":
                markings.append(marking_pap_red)
        if len(markings) == 0 and with_default:
            markings.append(marking_tlp_clear)
        return markings

    def resolve_tags(self, tags):
        opencti_tags = []

        if not self.misp_create_tags_as_labels:
            return opencti_tags

        for tag in tags:
            self.helper.log_info(f"found tag: {tag}")
            tag_name_lower = tag["name"].lower()
            # we take the tag as-is if it starts by a prefix stored in the keep_original_tags_as_label configuration
            if any(
                map(
                    lambda s: tag["name"].startswith(s),
                    self.keep_original_tags_as_label,
                )
            ):
                self.helper.log_info(f"keeping raw tag: {tag}")
                opencti_tags.append(tag["name"])

            elif (
                tag_name_lower != "tlp:white"
                and tag_name_lower != "tlp:clear"
                and tag_name_lower != "tlp:green"
                and tag_name_lower != "tlp:amber"
                and tag_name_lower != "tlp:amber+strict"
                and tag_name_lower != "tlp:red"
                and tag_name_lower != "pap:clear"
                and tag_name_lower != "pap:green"
                and tag_name_lower != "pap:amber"
                and tag_name_lower != "pap:red"
                and not tag["name"].startswith("misp-galaxy:threat-actor")
                and not tag["name"].startswith("misp-galaxy:mitre-threat-actor")
                and not tag["name"].startswith("misp-galaxy:microsoft-activity-group")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-threat-actor"
                )
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-mobile-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-intrusion-set")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-intrusion-set"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-malware")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-malware"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-attack-pattern")
                and not tag["name"].startswith(
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern"
                )
                and not tag["name"].startswith("misp-galaxy:mitre-tool")
                and not tag["name"].startswith("misp-galaxy:tool")
                and not tag["name"].startswith("misp-galaxy:ransomware")
                and not tag["name"].startswith("misp-galaxy:malpedia")
                and not tag["name"].startswith("misp-galaxy:sector")
                and not tag["name"].startswith("misp-galaxy:country")
                and not tag["name"].startswith("misp-galaxy:region")
                and not tag["name"].startswith("marking")
                and not tag["name"].startswith("creator")
                and not tag["name"].startswith("intrusion-set")
                and not tag["name"].startswith("malware")
                and not tag["name"].startswith("tool")
                and not tag["name"].startswith("mitre")
            ):
                tag_value = tag["name"]
                if '="' in tag["name"]:
                    tag_value_split = tag["name"].split('="')
                    if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                        tag_value = tag_value_split[1][:-1].strip()
                elif ":" in tag["name"]:
                    tag_value_split = tag["name"].split(":")
                    if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                        tag_value = tag_value_split[1].strip()
                if tag_value.isdigit():
                    if ":" in tag["name"]:
                        tag_value_split = tag["name"].split(":")
                        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                            tag_value = tag_value_split[1].strip()
                    else:
                        tag_value = tag["name"]
                if '="' in tag_value:
                    if len(tag_value) > 0:
                        tag_value = tag_value.replace('="', "-")[:-1]
                opencti_tags.append(tag_value)
        return opencti_tags

    def find_type_by_uuid(self, uuid, bundle_objects):
        # filter by uuid
        i_result = list(filter(lambda o: o.id.endswith("--" + uuid), bundle_objects))

        if len(i_result) > 0:
            uuid = i_result[0]["id"]
            return {
                "entity": i_result[0],
                "type": uuid[: uuid.index("--")],
            }
        return None

    # Markdown object, attribute & tag links should be converted from MISP links to OpenCTI links
    def process_note(self, content, bundle_objects):
        def reformat(match):
            type = match.group(1)
            uuid = match.group(2)
            result = self.find_type_by_uuid(uuid, bundle_objects)
            if result is None:
                return "[{}:{}](/dashboard/search/{})".format(type, uuid, uuid)
            if result["type"] == "indicator":
                name = result["entity"]["pattern"]
            else:
                name = result["entity"]["value"]
            return "[{}:{}](/dashboard/search/{})".format(
                type, name, result["entity"]["id"]
            )

        r_object = r"@\[(object|attribute)\]\(([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\)"
        r_tag = r'@\[tag\]\(([a-zA-Z:"\'0-9\-=]+)\)'

        content = re.sub(r_object, reformat, content, flags=re.MULTILINE)
        content = re.sub(r_tag, r"tag:\1", content, flags=re.MULTILINE)
        return content

    def threat_level_to_score(self, threat_level):
        if threat_level == "1":
            score = 90
        elif threat_level == "2":
            score = 60
        elif threat_level == "3":
            score = 30
        else:
            score = 50
        return score


if __name__ == "__main__":
    try:
        mispConnector = Misp()
        mispConnector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
