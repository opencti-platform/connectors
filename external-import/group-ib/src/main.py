import sys
import time
from traceback import format_exc

# WARN: python-dotenv is used for integration manual run
import dotenv
from adapter import DataToSTIXAdapter
from lib.external_import import ExternalImportConnector

dotenv.load_dotenv()


class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standardized way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _collect_intelligence(
        self, collection, ttl, event, mitre_mapper, flag=False
    ) -> []:
        """Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        # ===========================
        # === Add your code below ===
        # ===========================

        self.helper.log_debug("Collecting data")

        stix_objects = list()

        file_is_ioc = False
        domain_is_ioc = False
        url_is_ioc = False
        ip_is_ioc = False
        yara_is_ioc = False
        suricata_is_ioc = False
        email_is_ioc = False
        # ++
        if collection in [
            "apt/threat",
            "hi/threat",
            "apt/threat_actor",
            "hi/threat_actor",
        ]:
            url_is_ioc = True
            domain_is_ioc = True
            ip_is_ioc = True
            file_is_ioc = True
        elif collection in ["attacks/phishing_group"]:
            url_is_ioc = True
        elif collection in ["attacks/phishing_kit"]:
            email_is_ioc = True
        elif collection in ["malware/signature", "malware/yara"]:
            suricata_is_ioc = True
            yara_is_ioc = True
        elif collection in [
            "attacks/ddos",
            "attacks/deface",
            "malware/malware",
            "osi/vulnerability",
            "suspicious_ip/open_proxy",
            "suspicious_ip/scanner",
            "suspicious_ip/socks_proxy",
            "suspicious_ip/tor_node",
            "suspicious_ip/vpn",
        ]:
            domain_is_ioc = False
            url_is_ioc = False
            ip_is_ioc = False

        json_threat_report_obj = event.get("threat_report", {})
        json_file_obj = event.get("file", {})
        json_network_obj = event.get("network", {})
        json_yara_obj = event.get("yara_report", {})
        json_suricata_obj = event.get("suricata_report", {})
        json_cvss_obj = event.get("cvssv3", {})
        json_malware_report_obj = event.get("malware_report", {})
        json_threat_actor_obj = event.get("threat_actor", {})
        json_vulnerability_obj = event.get("vulnerability", {})
        json_ungrouped_obj = event.get("ungrouped", {})
        json_evaluation_obj = event.get("evaluation", {})
        json_mitre_matrix_obj = event.get("mitre_matrix", {})
        json_date_obj = event.get("date", {})

        json_date_obj["ttl"] = ttl

        self.helper.log_debug("Initializing adapter")

        report_adapter = DataToSTIXAdapter(
            mitre_mapper=mitre_mapper,
            collection=collection,
            tlp_color=json_evaluation_obj.get("tlp", "white"),
            helper=self.helper,
            is_ioc=True,
        )

        self.helper.log_debug(json_threat_actor_obj.get("name"))

        self.helper.log_debug("Generating STIX objects")

        stix_malware_list = report_adapter.generate_stix_malware(
            obj=json_malware_report_obj,
            json_date_obj=json_date_obj,
        )
        stix_attack_pattern_list = report_adapter.generate_stix_attack_pattern(
            obj=json_mitre_matrix_obj
        )
        stix_vulnerability_list = report_adapter.generate_stix_vulnerability(
            obj=json_vulnerability_obj,
            related_objects=[
                # stix_threat_actor
            ],
            json_date_obj=json_date_obj,
            json_cvss_obj=json_cvss_obj,
        )
        stix_intrusion_set = None
        if flag:
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        # stix_attack_pattern_list,
                        # stix_malware_list,
                        # stix_vulnerability_list,
                    ],
                    json_date_obj=json_date_obj,
                )
            )
            stix_intrusion_set = report_adapter.generate_stix_intrusion_set(
                obj=json_threat_actor_obj,
                related_objects=[
                    stix_attack_pattern_list,
                    stix_malware_list,
                    stix_vulnerability_list,
                    stix_threat_actor,
                ],
                json_date_obj=json_date_obj,
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[stix_intrusion_set],
                    json_date_obj=json_date_obj,
                    domain_is_ioc=domain_is_ioc,
                    url_is_ioc=url_is_ioc,
                    ip_is_ioc=ip_is_ioc,
                )
            )
            stix_file_list = report_adapter.generate_stix_file(
                obj=json_file_obj,
                related_objects=[stix_intrusion_set],
                json_date_obj=json_date_obj,
                file_is_ioc=file_is_ioc,
            )
        else:
            stix_threat_actor, stix_threat_actor_location_list = (
                report_adapter.generate_stix_threat_actor(
                    obj=json_threat_actor_obj,
                    related_objects=[
                        stix_attack_pattern_list,
                        stix_malware_list,
                        stix_vulnerability_list,
                    ],
                    json_date_obj=json_date_obj,
                )
            )
            stix_domain_list, stix_url_list, stix_ip_list = (
                report_adapter.generate_stix_network(
                    obj=json_network_obj,
                    related_objects=[stix_threat_actor],
                    json_date_obj=json_date_obj,
                    domain_is_ioc=domain_is_ioc,
                    url_is_ioc=url_is_ioc,
                    ip_is_ioc=ip_is_ioc,
                )
            )
            stix_file_list = report_adapter.generate_stix_file(
                obj=json_file_obj,
                related_objects=[stix_threat_actor],
                json_date_obj=json_date_obj,
                file_is_ioc=file_is_ioc,
            )
        stix_yara = report_adapter.generate_stix_yara(
            obj=json_yara_obj,
            related_objects=[stix_malware_list],
            json_date_obj=json_date_obj,
            yara_is_ioc=yara_is_ioc,
        )
        stix_suricata = report_adapter.generate_stix_suricata(
            obj=json_suricata_obj,
            related_objects=[stix_malware_list],
            json_date_obj=json_date_obj,
            suricata_is_ioc=suricata_is_ioc,
        )
        stix_ungrouped_list = report_adapter.generate_stix_ungrouped(
            obj=json_ungrouped_obj,
            related_objects=[stix_file_list],
            json_date_obj=json_date_obj,
            email_is_ioc=email_is_ioc,
        )

        x = list()
        if stix_file_list:
            [x.extend(ob.stix_objects) for ob in stix_file_list]
        if stix_domain_list:
            [x.extend(ob.stix_objects) for ob in stix_domain_list]
        if stix_url_list:
            [x.extend(ob.stix_objects) for ob in stix_url_list]
        if stix_ip_list:
            [x.extend(ob.stix_objects) for ob in stix_ip_list]
        if stix_attack_pattern_list:
            [x.extend(ob.stix_objects) for ob in stix_attack_pattern_list]
        if stix_malware_list:
            [x.extend(ob.stix_objects) for ob in stix_malware_list]
        if stix_vulnerability_list:
            [x.extend(ob.stix_objects) for ob in stix_vulnerability_list]
        if stix_intrusion_set:
            x += stix_intrusion_set.stix_objects
        if stix_threat_actor:
            x += stix_threat_actor.stix_objects
        if stix_threat_actor_location_list:
            [x.extend(ob.stix_objects) for ob in stix_threat_actor_location_list]
        if stix_yara:
            x += stix_yara.stix_objects
        if stix_suricata:
            x += stix_suricata.stix_objects
        if stix_ungrouped_list:
            [x.extend(ob.stix_objects) for ob in stix_ungrouped_list]

        stix_report = report_adapter.generate_stix_report(
            obj=json_threat_report_obj,
            json_date_obj=json_date_obj,
            report_related_objects_ids=[_.id for _ in x],
            json_malware_report_obj=json_malware_report_obj,
            json_threat_actor_obj=json_threat_actor_obj,
        )

        self.helper.log_debug("Pack objects")

        if stix_report:
            x += stix_report.stix_objects
            x += [stix_report.author]
            x += [stix_report.tlp]
        else:
            if any(x):
                x += [report_adapter.author]

        stix_objects += x

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception:
        print(format_exc())
        time.sleep(10)
        sys.exit(0)
