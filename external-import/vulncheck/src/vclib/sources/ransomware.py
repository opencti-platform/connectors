from datetime import datetime

# from vclib.connector import ConnectorVulnCheck


def collect_ransomware(conn, config_state: dict) -> list:
    """Collect all data for the ransomware source

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[RANSOMWARE] Starting collection")
    entities = conn.client.get_ransomware()
    stix_objects = []

    conn.helper.connector_logger.info("[RANSOMWARE] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[RANSOMWARE] Creating malware object",
            {"ransomware_name": entity.ransomware_family},
        )
        malware = conn.converter_to_stix.create_malware(
            name=entity.ransomware_family,
            is_family=True,
            first_seen=datetime.fromisoformat(entity.date_added),
        )

        stix_objects.append(malware)

        if entity.cve is not None:
            for cve in entity.cve:
                conn.helper.connector_logger.debug(
                    "[RANSOMWARE] Creating vulnerability object",
                    {"cve": cve},
                )
                vuln = conn.converter_to_stix.create_vulnerability(cve)

                conn.helper.connector_logger.debug(
                    '[RANSOMWARE] Creating "exploits" relationship',
                )
                malware_vuln_relationship = conn.converter_to_stix.create_relationship(
                    malware["id"], "exploits", vuln["id"]
                )
                stix_objects.append(vuln)
                stix_objects.append(malware_vuln_relationship)

    conn.helper.connector_logger.info("[RANSOMWARE] Data Source Completed!")
    return stix_objects
