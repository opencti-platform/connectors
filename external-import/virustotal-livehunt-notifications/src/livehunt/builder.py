# -*- coding: utf-8 -*-
"""Livehunt builder module."""
import datetime
import io
import logging
import re
from typing import List, Optional

import magic
import plyara
import plyara.utils
import stix2
import vt
from pycti import Incident, Indicator, OpenCTIConnectorHelper, StixCoreRelationship

logging.getLogger("plyara").setLevel(logging.ERROR)


class LivehuntBuilder:
    """Virustotal Livehunt builder."""

    _SOURCE = "hunting_notification"

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        author_name: str,
        tag: str,
        create_alert: bool,
        max_age_days: int,
        create_file: bool,
        upload_artifact: bool,
        create_yara_rule: bool,
        delete_notification: bool,
        extensions: list[str],
        min_file_size: int,
        max_file_size: int,
        min_positives: int,
        alert_prefix: str,
        av_list: list[str],
        yara_label_prefix: str,
        livehunt_label_prefix: str,
        livehunt_tag_prefix: str,
        enable_label_enrichment: bool,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.author_name = author_name
        self.bundle = []
        self.tag = tag
        self.with_alert = create_alert
        self.max_age_days = max_age_days
        self.with_file = create_file
        self.upload_artifact = upload_artifact
        self.with_yara_rule = create_yara_rule
        self.delete_notification = delete_notification
        self.extensions = extensions
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.min_positives = min_positives
        self.alert_prefix = alert_prefix
        self.av_list = av_list
        self.yara_label_prefix = yara_label_prefix
        self.livehunt_label_prefix = livehunt_label_prefix
        self.livehunt_tag_prefix = livehunt_tag_prefix
        self.enable_label_enrichment = enable_label_enrichment

    def process(self, start_date: str, timestamp: int):
        # Work id will only be set and instantiated if there are bundles to send.
        work_id = None
        url = "/ioc_stream"
        filter = f"date:{start_date}+ source_type:hunting_ruleset"
        if self.tag is not None and self.tag != "":
            self.helper.connector_logger.debug(f"Setting up filter with tag {self.tag}")
            filter += f" notification_tag:{self.tag}"

        params = {
            "descriptors_only": "False",
            "filter": filter,
        }
        self.helper.connector_logger.info(
            f"Url for notifications: {url} / params: {params}"
        )

        files_iterator = self.client.iterator(url, params=params)

        for vtobj in files_iterator:

            if self.delete_notification:
                self.delete_livehunt_notification(vtobj.id)

            if self.upload_artifact:
                if not self.artifact_exists_opencti(vtobj.sha256):
                    self.upload_artifact_opencti(vtobj)

            # If extension filters were set
            if self.extensions:
                # If the extension isn't in the list of extensions
                if not hasattr(vtobj, "type_extension"):
                    continue
                elif vtobj.type_extension not in self.extensions:
                    self.helper.connector_logger.info(
                        f"Extension {vtobj.type_extension} not in filter {self.extensions}."
                    )
                    continue

            # If min positives set and file has fewer detections
            if (
                not hasattr(vtobj, "last_analysis_stats")
                or not self.min_positives
                or vtobj.last_analysis_stats.get("malicious", 0) < self.min_positives
            ):
                self.helper.connector_logger.info("Not enough detections")
                continue

            # If min size was set and file is below that size
            if self.min_file_size and self.min_file_size > int(vtobj.size):
                self.helper.connector_logger.info(
                    f"File too small ({vtobj.size} < {self.min_file_size}"
                )
                continue

            # If max size was set and file is above that size
            if self.max_file_size and self.max_file_size < int(vtobj.size):
                self.helper.connector_logger.info(
                    f"File too big ({vtobj.size} > {self.max_file_size}"
                )
                continue

            if self.max_age_days is not None:
                time_diff = datetime.datetime.now() - vtobj.first_submission_date
                if time_diff.days >= self.max_age_days:
                    self.helper.connector_logger.info(
                        f"First submission date {vtobj.first_submission_date} is too old (more than {self.max_age_days} days"
                    )
                    continue

            # Create external reference to Virustotal report
            external_reference = self.create_external_reference(
                f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
                "Virustotal Analysis",
            )
            incident_id = None
            file_id = None

            if self.with_alert:
                incident_id = self.create_alert(vtobj, external_reference)

            if self.with_file:
                file_id = self.create_file(vtobj, incident_id)

            if self.with_yara_rule:
                for source in vtobj._context_attributes["sources"]:
                    self.create_rule(
                        source["id"],
                        source["label"],
                        incident_id,
                        file_id,
                    )

            if len(self.bundle) > 0:
                if work_id is None:
                    work_id = self.initiate_work(timestamp)
                self.send_bundle(work_id)

    def artifact_exists_opencti(self, sha256: str) -> bool:
        """
        Determine whether an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "hashes.SHA-256", "values": [sha256]}],
                "filterGroups": [],
            }
        )

        if response:
            return True
        return False

    def create_alert(self, vtobj, external_reference) -> str:
        """
        Create the alert from the livehunt notifications.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        external_reference : stix2.ExternalReference
            External reference to the file on VirusTotal.

        Returns
        -------
        str
            Id of the created incident.
        """
        # Create the alert
        name = f"""{self.alert_prefix} {vtobj._context_attributes["hunting_info"]["rule_name"]} file={vtobj.sha256}"""
        incident_id = Incident.generate_id(
            name, vtobj._context_attributes["notification_date"]
        )
        alert = self.helper.api.incident.read(id=incident_id)
        if alert:
            self.helper.connector_logger.info(
                f"Alert {alert['id']} already exists, skipping"
            )
            return None
        incident = stix2.Incident(
            id=incident_id,
            incident_type="alert",
            name=name,
            description=f'Date of the alert on VirusTotal: {datetime.datetime.fromtimestamp(vtobj._context_attributes["notification_date"])}',
            source=self._SOURCE,
            created_by_ref=self.author["standard_id"],
            confidence=self.helper.connect_confidence_level,
            labels=self.retrieve_labels(vtobj),
            external_references=[external_reference],
            allow_custom=True,
        )
        self.helper.connector_logger.debug(f"Adding alert: {incident}")
        self.bundle.append(incident)
        return incident["id"]

    def create_external_reference(self, url: str, description: str):
        """
        Create an external reference.

        Used to have a link to the file on VirusTotal.

        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description fot the external reference.

        Returns
        -------
        stix2.ExternalReference
            The external reference object.
        """
        external_reference = stix2.ExternalReference(
            source_name=self.author_name,
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author["standard_id"],
            },
        )
        return external_reference

    def create_file(self, vtobj, incident_id: Optional[str] = None) -> str:
        """
        Create a file and link it to the created incident, if any.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.

        Returns
        -------
        str
            Id of the created file.
        """
        vt_score = None
        try:
            if hasattr(vtobj, "last_analysis_stats"):
                vt_score = self._compute_score(vtobj.last_analysis_stats)
        except ZeroDivisionError as e:
            self.helper.metric.inc("error_count")
            self.helper.connector_logger.error(
                f"Unable to compute score of file, err = {e}"
            )

        external_reference = self.create_external_reference(
            f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
            "Virustotal Analysis",
        )

        ## Add the additional name
        x_opencti_additional_names = []
        for name in vtobj.names:
            if name != vtobj.meaningful_name:
                x_opencti_additional_names.append(name)

        ## Build a description using the last analysis data from av
        description = ""
        for av in self.av_list:
            av_result = vtobj.last_analysis_results.get(av, {}).get("result")
            description += f"- **{av}**: {av_result}\n"

        # Add the score to the description
        # if score is not None:
        description += f"\nVirusTotal's score: {vt_score}%.\n"

        # add labels from common tags:
        labels = []
        for tag in vtobj.type_tags:
            labels.append(f"{self.livehunt_tag_prefix}{self._normalize_label(tag)}")
        for tag in vtobj.tags:
            labels.append(f"{self.livehunt_tag_prefix}{self._normalize_label(tag)}")

        file = stix2.File(
            type="file",
            name=f'{vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else "unknown"}',
            description=description,
            hashes={
                "MD5": vtobj.md5,
                "SHA256": vtobj.sha256,
                "SHA1": vtobj.sha1,
            },
            size=vtobj.size,
            external_references=[external_reference],
            custom_properties={
                "x_opencti_score": vt_score,
                "created_by_ref": self.author["standard_id"],
                "x_opencti_additional_names": x_opencti_additional_names,
            },
            allow_custom=True,
            labels=labels,
        )
        self.bundle.append(file)
        # Link to the incident if any.
        if incident_id is not None:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    incident_id,
                    file["id"],
                ),
                relationship_type="related-to",
                created_by_ref=self.author["standard_id"],
                source_ref=incident_id,
                target_ref=file["id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle.append(relationship)
        return file["id"]

    def create_rule(
        self,
        ruleset_id: str,
        rule_name: str,
        incident_id: Optional[str] = None,
        file_id: Optional[str] = None,
    ):
        """
        Get the rule from VirusTotal, parse the yara rules and create the wanted rule.

        A single rule is created, the one having the name matching.
        If an incident or a file has been created, the yara rules will be linked to them.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id of the notification to retrieve.
        rule_name : str
            Name of the rule that matched.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.
        file_id : str, optional
            Id of the file to be linked to the file using a `related-to` relationship.
        """
        ruleset = self.client.get_object(f"/intelligence/hunting_rulesets/{ruleset_id}")

        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset.rules)

        for rule in rules:
            if rule["rule_name"] == rule_name:
                self.helper.connector_logger.debug(f"Adding rule name {rule_name}")
                # Default valid_from with current date
                valid_from = self.helper.api.stix2.format_date(
                    datetime.datetime.utcnow()
                )
                try:
                    valid_from = self.helper.api.stix2.format_date(
                        next(
                            (
                                i["date"]
                                for i in rule.get("metadata", {})
                                if "date" in i
                            ),
                            None,
                        )
                    )
                except ValueError as e:
                    self.helper.connector_logger.error(
                        f"Date not valid, setting to {valid_from}, err: {e}"
                    )

                indicator = stix2.Indicator(
                    id=Indicator.generate_id(plyara.utils.rebuild_yara_rule(rule)),
                    created_by_ref=self.author["standard_id"],
                    name=rule["rule_name"],
                    description=next(
                        (i["date"] for i in rule.get("metadata", {}) if "date" in i),
                        "No description",
                    ),
                    confidence=self.helper.connect_confidence_level,
                    pattern=plyara.utils.rebuild_yara_rule(rule),
                    pattern_type="yara",
                    valid_from=valid_from,
                    custom_properties={
                        "x_opencti_main_observable_type": "StixFile",
                    },
                )
                self.helper.connector_logger.debug(
                    f"[VirusTotal Livehunt Notifications] yara indicator created: {indicator}"
                )
                self.bundle.append(indicator)

                if incident_id is not None:
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            incident_id,
                            indicator["id"],
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.author["standard_id"],
                        source_ref=incident_id,
                        target_ref=indicator["id"],
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                    self.bundle.append(relationship)

                if file_id is not None:
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            file_id,
                            indicator["id"],
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.author["standard_id"],
                        source_ref=file_id,
                        target_ref=indicator["id"],
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                    self.bundle.append(relationship)

    def delete_livehunt_notification(self, notification_id):
        """
        Delete a Livehunt Notification.

        Parameters
        ----------
        notification_id : str
            Io of the notification to delete.
        """
        url = f"/intelligence/hunting_notifications/{notification_id}"
        return self.client.delete(url)

    def initiate_work(self, timestamp: int) -> str:
        now = datetime.datetime.utcfromtimestamp(timestamp)
        friendly_name = "Virustotal Livehunt Notifications run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.connector_logger.info(
            f"[Virustotal Livehunt Notifications] workid {work_id} initiated"
        )
        return work_id

    def send_bundle(self, work_id: str):
        """
        Send the bundle to OpenCTI.

        After being sent, the bundle is reset.

        Parameters
        ----------
        work_id : str
            Work id to use
        """
        self.helper.metric.inc("record_send", len(self.bundle))
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.connector_logger.debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = []

    def upload_artifact_opencti(self, vtobj):
        """Upload a file to OpenCTI."""
        file_name = (
            vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else vtobj.sha256
        )

        # Download the file to a file like object
        file_obj = io.BytesIO()
        self.helper.connector_logger.info(f"Downloading {vtobj.sha256}")
        self.client.download_file(vtobj.sha256, file_obj)
        file_obj.seek(0)
        file_contents = file_obj.read()

        mime_type = magic.from_buffer(file_contents, mime=True)

        kwargs = {
            "file_name": file_name,
            "data": file_contents,
            "mime_type": mime_type,
            "x_opencti_description": "Downloaded from Virustotal Livehunt Notifications.",
            "createdBy": self.author["standard_id"],
        }
        return self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

    def retrieve_labels(self, vtobj) -> List[str]:
        ctx_attributes = vtobj._context_attributes
        labels = [t for t in ctx_attributes["tags"] if t not in {vtobj.id, self.tag}]

        if not self.enable_label_enrichment:
            return labels

        # retrieve the live-hunt related label
        live_hunt_label = ctx_attributes["hunting_info"]["rule_name"]
        if live_hunt_label is not None:
            live_hunt_label = self._normalize_label(live_hunt_label)
            labels = list(filter(lambda s: s != live_hunt_label, labels))
            labels.append(f"{self.livehunt_label_prefix}{live_hunt_label}")

        # retrieve the yara rule names that triggered for this sample
        for source in ctx_attributes["sources"]:
            if source.get("type") != "hunting_ruleset":
                continue

            source_label = self._normalize_label(source["label"])
            labels = list(filter(lambda s: s != source_label, labels))
            labels.append(f"{self.yara_label_prefix}{source_label}")

        return labels

    @staticmethod
    def _normalize_label(label: str) -> str:
        """Based on livehunt's label normalization"""
        return re.sub("[^a-z0-9]", "_", label.lower())

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as e:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable"
            ) from e
        return vt_score
