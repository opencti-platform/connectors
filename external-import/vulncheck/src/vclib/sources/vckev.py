# from vclib.connector import ConnectorVulnCheck


def collect_vckev(conn, config_state: dict) -> list:
    """Collect all data for vulncheck-kev

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[VULNCHECK KEV] Starting collection")
    entities = conn.client.get_vckev()
    stix_objects = []

    conn.helper.connector_logger.info("[VULNCHECK KEV] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[VULNCHECK KEV] Creating vulnerability",
            {"cve": entity.cve[0]},
        )
        vuln = conn.converter_to_stix.create_vulnerability(
            cve=entity.cve[0],
        )
        stix_objects.append(vuln)

    conn.helper.connector_logger.info("[VULNCHECK KEV] Data Source Completed!")
    return stix_objects
