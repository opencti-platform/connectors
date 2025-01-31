# from vclib.connector import ConnectorVulnCheck

from vclib.sources import data_source

from .util import parse_cpe_uri


def collect_vcnvd2(conn, config_state: dict) -> list:
    """Collect all data for vulncheck-nvd2

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[VULNCHECK NVD-2] Starting collection")
    entities = (
        conn.client.get_vcnvd2()
        if config_state is not None and data_source.VULNCHECK_NVD2 in config_state
        else conn.client.get_vcnvd2_from_backup()
    )
    stix_objects = []

    conn.helper.connector_logger.info(
        "[VULNCHECK NVD-2] Parsing data into STIX objects"
    )
    for entity in entities:
        vuln = None
        conn.helper.connector_logger.debug(
            "[VULNCHECK NVD-2] Creating vulnerability object",
            {"cve": entity.id},
        )

        if entity.metrics is not None and entity.metrics.cvss_metric_v31 is not None:
            cvss_data = entity.metrics.cvss_metric_v31[0].cvss_data
            custom_properties = {
                "x_opencti_cvss_base_score": cvss_data.base_score,
                "x_opencti_cvss_base_severity": cvss_data.base_severity,
                "x_opencti_cvss_attack_vector": cvss_data.attack_vector,
            }
            vuln = conn.converter_to_stix.create_vulnerability(
                cve=entity.id, custom_properties=custom_properties
            )
        elif entity.metrics is not None and entity.metrics.cvss_metric_v30 is not None:
            cvss_data = entity.metrics.cvss_metric_v30[0].cvss_data
            custom_properties = {
                "x_opencti_cvss_base_score": cvss_data.base_score,
                "x_opencti_cvss_base_severity": cvss_data.base_severity,
                "x_opencti_cvss_attack_vector": cvss_data.attack_vector,
            }
            vuln = conn.converter_to_stix.create_vulnerability(
                cve=entity.id, custom_properties=custom_properties
            )
        else:
            vuln = conn.converter_to_stix.create_vulnerability(entity.id)

        stix_objects.append(vuln)

        if entity.vc_vulnerable_cpes is not None:
            for cpe in entity.vc_vulnerable_cpes:
                cpe_dict = parse_cpe_uri(cpe)

                conn.helper.connector_logger.debug(
                    "[VULNCHECK NVD-2] Creating software object",
                    {"software": cpe_dict["product"]},
                )
                software = conn.converter_to_stix.create_software(
                    product=cpe_dict["product"],
                    vendor=cpe_dict["vendor"],
                    version=cpe_dict["version"],
                    cpe=cpe,
                )

                conn.helper.connector_logger.debug(
                    '[VULNCHECK NVD-2] Creating "has" relationship',
                )
                software_vuln_relationship = conn.converter_to_stix.create_relationship(
                    source_id=software["id"],
                    relationship_type="has",
                    target_id=vuln["id"],
                )

                stix_objects.append(software)
                stix_objects.append(software_vuln_relationship)

    conn.helper.connector_logger.info("[VULNCHECK NVD-2] Data Source Completed!")
    return stix_objects
