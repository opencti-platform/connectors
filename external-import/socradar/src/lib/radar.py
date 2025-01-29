# ===============================================================================
# Imports: System and Third-Party Libraries
# ===============================================================================
import json
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Dict

import requests
import yaml

# ===============================================================================
# Imports: OpenCTI Libraries
# ===============================================================================
# PyCTI
from pycti import Identity as PyctiIdentity
from pycti import Indicator as PyctiIndicator
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable

# STIX2
from stix2 import TLP_WHITE, Bundle
from stix2 import Identity as Stix2Identity
from stix2 import Indicator as Stix2Indicator

# ===============================================================================
# Constants
# ===============================================================================
BATCH_SIZE = 1000
DEFAULT_INTERVAL = 600
DEFAULT_CONFIDENCE = 75
TLP_MARKING = TLP_WHITE.id


# ===============================================================================
# Main Operator: RadarConnector
# ===============================================================================
class RadarConnector:
    """
    OpenCTI connector for SOCRadar threat intelligence feeds.
    Processes indicators in batches and creates STIX2 objects.
    """

    def __init__(self) -> None:
        """Initialize RadarConnector with configuration and helpers"""
        # Step 1.0: Set up configuration paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "..", "config.yml")

        # Step 1.1: Load configuration file
        if os.path.isfile(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
        else:
            config = {}

        # Step 2.0: Initialize OpenCTI helper
        self.helper = OpenCTIConnectorHelper(config)

        # Step 3.0: Configure feed parameters
        # Step 3.1: Set base URL and API key
        self.base_url = get_config_variable(
            "RADAR_BASE_FEED_URL", ["radar", "radar_base_feed_url"], config
        )
        self.socradar_key = get_config_variable(
            "RADAR_SOCRADAR_KEY", ["radar", "radar_socradar_key"], config
        )

        # Step 3.2: Set run interval
        self.interval = get_config_variable(
            "RADAR_RUN_INTERVAL",
            ["radar", "radar_run_interval"],
            config,
            default=DEFAULT_INTERVAL,
        )
        if isinstance(self.interval, str):
            self.interval = int(self.interval)

        # Step 3.3: Configure collections
        raw_collections = get_config_variable(
            "RADAR_COLLECTIONS_UUID", ["radar", "radar_collections_uuid"], config
        )
        if isinstance(raw_collections, str):
            try:
                self.collections = json.loads(raw_collections)
            except Exception:
                self.collections = {}
        else:
            self.collections = raw_collections or {}

        # Step 3.4: Set format type for API requests
        self.format_type = ".json?key="

        # Step 4.0: Initialize caches and patterns
        self.identity_cache: Dict[str, Stix2Identity] = {}
        self.regex_patterns = {
            "md5": r"^[a-fA-F\d]{32}$",
            "sha1": r"^[a-fA-F\d]{40}$",
            "sha256": r"^[a-fA-F\d]{64}$",
            "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
            "ipv6": r"^(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}$",
            "domain": r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$",
            "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        }

    # ===============================================================================
    # Utility Methods
    # ===============================================================================
    def _matches_pattern(self, value: str, pattern_name: str) -> bool:
        """Match value against regex pattern"""
        return bool(re.match(self.regex_patterns[pattern_name], value))

    def _validate_dates(self, first_seen: str, last_seen: str):
        """Validate and convert date strings to datetime objects"""
        # Step 1.0: Set datetime format
        dt_format = "%Y-%m-%d %H:%M:%S"

        # Step 1.1: Convert strings to datetime objects
        valid_from = datetime.strptime(first_seen, dt_format)
        valid_until = datetime.strptime(last_seen, dt_format)

        # Step 1.2: Ensure valid time range
        if valid_until <= valid_from:
            valid_until = valid_from + timedelta(hours=1)

        return valid_from, valid_until

    def _create_stix_pattern(self, value: str, feed_type: str) -> str:
        """
        Build a STIX pattern from feed_type or fallback detection
        (handles ip, domain, url, hash, etc.)
        """
        # If feed_type is "ip", check IPv4 or IPv6
        if feed_type == "ip":
            if self._matches_pattern(value, "ipv4"):
                return f"[ipv4-addr:value = '{value}']"
            elif self._matches_pattern(value, "ipv6"):
                return f"[ipv6-addr:value = '{value}']"

        known_patterns = {
            "url": lambda v: f"[url:value = '{v}']",
            "domain": lambda v: f"[domain-name:value = '{v}']",
            "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
            "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
            "md5": lambda v: f"[file:hashes.'MD5' = '{v}']",
            "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        }

        if feed_type in known_patterns:
            return known_patterns[feed_type](value)

        # Fallback detection
        for ptype, regex in self.regex_patterns.items():
            if re.match(regex, value):
                # e.g. ptype=md5 => "[file:hashes.'MD5' = '...']"
                if ptype in known_patterns:
                    return known_patterns[ptype](value)

        # Otherwise, custom
        return f"[x-custom:value = '{value}']"

    def _get_or_create_identity(self, maintainer_name: str):
        """
        Use pycti.Identity.generate_id(...) for stable dedup
        Return a stix2.Identity w/ that ID
        """
        if maintainer_name in self.identity_cache:
            return self.identity_cache[maintainer_name]

        try:
            identity_id = PyctiIdentity.generate_id(
                name=maintainer_name,
                identity_class="organization",
            )
            now = datetime.utcnow()
            identity = Stix2Identity(
                id=identity_id,
                name=maintainer_name,
                identity_class="organization",
                description=f"Feed Provider: {maintainer_name}",
                created=now,
                modified=now,
            )
            self.identity_cache[maintainer_name] = identity
            return identity
        except Exception as e:
            self.helper.log_error(
                f"Error creating Identity for {maintainer_name}: {str(e)}"
            )
            return None

    ########################################################################
    # Feed Processing
    ########################################################################

    def _process_feed_item(self, item: dict):
        """Process single feed item into STIX objects"""
        # Step 1.0: Initialize empty list for STIX objects
        stix_objects = []

        # Step 2.0: Extract core fields from feed item
        # Step 2.1: Get primary indicator value
        value = item.get("feed")
        # Step 2.2: Get indicator type (default to IP if not specified)
        feed_type = item.get("feed_type", "ip").lower()
        # Step 2.3: Get source/maintainer information
        maintainer = item.get("maintainer_name", "Unknown")

        # Step 3.0: Extract and validate timestamp fields
        # Step 3.1: Get first seen date
        first_seen_str = item.get("first_seen_date")
        # Step 3.2: Get last seen date
        last_seen_str = item.get("latest_seen_date")
        # Step 3.3: Validate required fields exist
        if not (value and first_seen_str and last_seen_str):
            self.helper.log_error(f"Item missing fields: {item}")
            return stix_objects

        # Step 4.0: Convert and validate dates
        valid_from, valid_until = self._validate_dates(first_seen_str, last_seen_str)

        # Step 5.0: Create or get cached identity object
        identity_obj = self._get_or_create_identity(maintainer)
        if not identity_obj:
            return stix_objects

        # Step 6.0: Generate STIX pattern for indicator
        pattern = self._create_stix_pattern(value, feed_type)
        if not pattern:
            self.helper.log_error(
                f"Could not determine pattern for: {value} / {feed_type}"
            )
            return stix_objects

        # Step 7.0: Generate stable indicator ID
        try:
            indicator_id = PyctiIndicator.generate_id(pattern)
        except Exception as e:
            self.helper.log_error(f"Indicator ID generation error: {str(e)}")
            return stix_objects

        # Step 8.0: Create STIX2 Indicator object
        indicator = Stix2Indicator(
            id=indicator_id,
            name=f"{feed_type.upper()}: {value}",
            description=f"Source: {maintainer}\nValue: {value}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            valid_until=valid_until,
            created_by_ref=identity_obj.id,
            object_marking_refs=[TLP_WHITE.id],
            labels=["malicious-activity", feed_type],
            confidence=75,
            created=valid_from,
            modified=valid_from,
        )

        # Step 9.0: Create relationship between indicator and identity
        # Step 9.1: Generate stable relationship ID
        relationship_id = StixCoreRelationship.generate_id(
            "created-by", indicator.id, identity_obj.id
        )
        # Step 9.2: Format timestamps for relationship
        created_str = valid_from.strftime("%Y-%m-%dT%H:%M:%SZ")
        modified_str = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Step 9.3: Build relationship object
        relationship_obj = {
            "id": relationship_id,
            "type": "relationship",
            "spec_version": "2.1",
            "x_opencti_type": "stix-core-relationship",
            "relationship_type": "created-by",
            "source_ref": indicator.id,
            "target_ref": identity_obj.id,
            "created": created_str,
            "modified": modified_str,
            "confidence": 75,
            "object_marking_refs": [TLP_WHITE.id],
        }

        # Step 10.0: Combine all STIX objects
        stix_objects.extend([identity_obj, indicator, relationship_obj])
        # Step 10.1: Log success
        self.helper.log_info(
            f"Created {feed_type} indicator => {value} from {maintainer}"
        )
        # Step 10.2: Return combined objects
        return stix_objects

    def _process_feed(self, work_id: str):
        """
        Batched feed ingestion in chunks of 1000 items
        """
        self.helper.log_info("RadarConnector: Starting feed collection...")

        for collection_name, collection_data in self.collections.items():
            try:
                # Build feed URL
                coll_id = collection_data["id"][0]
                feed_url = (
                    f"{self.base_url}{coll_id}{self.format_type}{self.socradar_key}&v=2"
                )

                self.helper.log_info(
                    f"Fetching data from {collection_name} => {feed_url}"
                )
                resp = requests.get(feed_url, timeout=30)
                resp.raise_for_status()
                items = resp.json()
                self.helper.log_info(f"Got {len(items)} items from {collection_name}")

                stix_batch = []
                total_sent = 0

                for idx, item in enumerate(items, start=1):
                    new_objs = self._process_feed_item(item)
                    if new_objs:
                        stix_batch.extend(new_objs)

                    # If we reached a batch boundary
                    if idx % BATCH_SIZE == 0:
                        bundle = Bundle(objects=stix_batch, allow_custom=True)
                        self.helper.send_stix2_bundle(
                            bundle.serialize(), work_id=work_id
                        )
                        total_sent += len(stix_batch)
                        self.helper.log_info(
                            f"Sent batch of {len(stix_batch)} objects (total: {total_sent})"
                        )
                        stix_batch = []

                # Final leftover
                if stix_batch:
                    bundle = Bundle(objects=stix_batch, allow_custom=True)
                    self.helper.send_stix2_bundle(bundle.serialize(), work_id=work_id)
                    total_sent += len(stix_batch)
                    self.helper.log_info(
                        f"Sent final batch of {len(stix_batch)} objects (total: {total_sent})"
                    )

            except Exception as e:
                self.helper.log_error(f"Failed to process {collection_name}: {str(e)}")

    ########################################################################
    # Connector Workflow
    ########################################################################
    def process_message(self):
        """
        Called each run. Create "Work", process feed, finalize.
        """
        self.helper.log_info("RadarConnector: process_message started.")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        friendly_name = f"SOCRadar Connector run @ {now_str}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        try:
            self._process_feed(work_id)
            message = "Radar feed import complete"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("RadarConnector interrupted. Stopping.")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(f"process_message error: {str(e)}")

    def run(self):
        """
        Run in start-up.
        Mainly runs with OpenCTI's schedule_iso.
        """
        # Step 1.0: Run immediately on startup
        self.helper.log_info("Running initial collection...")
        self.process_message()

        # Step 2.0: Schedule recurring runs
        duration_period = f"PT{self.interval}S"  # e.g., PT600S for 10 minutes
        self.helper.log_info(f"Scheduling recurring runs every {self.interval} seconds")

        self.helper.schedule_iso(
            message_callback=self.process_message, duration_period=duration_period
        )
