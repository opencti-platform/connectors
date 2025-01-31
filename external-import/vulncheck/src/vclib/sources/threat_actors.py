from datetime import datetime

# from vclib.connector import ConnectorVulnCheck


def collect_threat_actors(conn, config_state: dict) -> list:
    """Collect all data for the threat actors source

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[THREAT ACTORS] Starting collection")
    entities = conn.client.get_threat_actors()
    stix_objects = []

    conn.helper.connector_logger.info("[THREAT ACTORS] Parsing data into STIX objects")
    for entity in entities:
        threat_actor_external_refs = []
        vulnerabilities = []

        for reference in entity.cve_references:
            conn.helper.connector_logger.debug(
                "[THREAT ACTORS] Creating external reference",
                {"ref_url": reference.url},
            )
            external_ref = conn.converter_to_stix.create_external_reference(
                reference.url, reference.url
            )
            threat_actor_external_refs.append(external_ref)

            for cve in reference.cve:
                conn.helper.connector_logger.debug(
                    "[THREAT ACTORS] Creating vulnerability",
                    {"cve": cve},
                )
                vuln = conn.converter_to_stix.create_vulnerability(cve)
                vulnerabilities.append(vuln)

        conn.helper.connector_logger.debug(
            "[THREAT ACTORS] Creating threat actor group",
            {"threat_actor": entity.threat_actor_name},
        )
        threat_actor = conn.converter_to_stix.create_threat_actor_group(
            name=entity.threat_actor_name,
            first_seen=datetime.fromisoformat(entity.date_added),
            external_refs=threat_actor_external_refs,
        )
        stix_objects.append(threat_actor)

        for vuln in vulnerabilities:
            conn.helper.connector_logger.debug(
                '[THREAT ACTORS] Creating "targets" relationship',
            )
            threat_actor_vuln_relationship = conn.converter_to_stix.create_relationship(
                threat_actor["id"], "targets", vuln["id"]
            )
            stix_objects.append(vuln)
            stix_objects.append(threat_actor_vuln_relationship)

    conn.helper.connector_logger.info("[THREAT ACTORS] Data Source Completed!")
    return stix_objects
