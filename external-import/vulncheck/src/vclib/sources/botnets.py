from stix2.v21.vocab import INFRASTRUCTURE_TYPE_BOTNET

# from vclib.connector import ConnectorVulnCheck


def collect_botnets(conn, config_state: dict) -> list:
    """Collect all data for the botnets source

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[BOTNET] Starting collection")
    entities = conn.client.get_botnets()
    stix_objects = []

    conn.helper.connector_logger.info("[BOTNET] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[BOTNET] Creating infrastructure of type botnet",
            {"botnet_name": entity.botnet_name},
        )

        botnet = conn.converter_to_stix.create_infrastructure(
            name=entity.botnet_name,
            infrastructure_type=INFRASTRUCTURE_TYPE_BOTNET,
        )
        stix_objects.append(botnet)

        for cve in entity.cve:
            conn.helper.connector_logger.debug(
                "[BOTNET] Creating vulnerability",
                {"cve": cve},
            )
            vuln = conn.converter_to_stix.create_vulnerability(cve)

            conn.helper.connector_logger.debug(
                '[BOTNET] Creating "related-to" relationship',
            )
            botnet_vuln_relationship = conn.converter_to_stix.create_relationship(
                botnet["id"], "related-to", vuln["id"]
            )
            stix_objects.append(vuln)
            stix_objects.append(botnet_vuln_relationship)

    conn.helper.connector_logger.info("[BOTNET] Data Source Completed!")
    return stix_objects
