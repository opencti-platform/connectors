# from vclib.connector import ConnectorVulnCheck

from .util import parse_cpe_uri


def collect_initial_access(conn, config_state: dict) -> list:
    """Collect all data for the initial access source

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[INITIAL ACCESS] Starting collection")
    entities = conn.client.get_initial_access()
    stix_objects = []

    conn.helper.connector_logger.info("[INITIAL ACCESS] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[INITIAL ACCESS] Creating vulnerability object",
            {"cve": entity.cve},
        )

        custom_properties = {
            "x_opencti_cisa_kev": entity.in_kev,
        }
        vuln = conn.converter_to_stix.create_vulnerability(
            entity.cve, custom_properties=custom_properties
        )

        stix_objects.append(vuln)

        if entity.vulnerable_cpes is not None:
            for cpe in entity.vulnerable_cpes:
                cpe_dict = parse_cpe_uri(cpe)

                conn.helper.connector_logger.debug(
                    "[INITIAL ACCESS] Creating software object",
                    {"software": cpe_dict["product"]},
                )
                software = conn.converter_to_stix.create_software(
                    product=cpe_dict["product"],
                    vendor=cpe_dict["vendor"],
                    version=cpe_dict["version"],
                    cpe=cpe,
                )

                conn.helper.connector_logger.debug(
                    '[INITIAL ACCESS] Creating "has" relationship',
                )
                software_vuln_relationship = conn.converter_to_stix.create_relationship(
                    source_id=software["id"],
                    relationship_type="has",
                    target_id=vuln["id"],
                )

                stix_objects.append(software)
                stix_objects.append(software_vuln_relationship)

    conn.helper.connector_logger.info("[INITIAL ACCESS] Data Source Completed!")
    return stix_objects
