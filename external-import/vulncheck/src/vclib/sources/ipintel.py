from datetime import datetime

from stix2.v21.vocab import INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL

# from vclib.connector import ConnectorVulnCheck


def collect_ipintel(conn, config_state: dict) -> list:
    """Collect all data for the botnets source

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[IP INTEL] Starting collection")
    entities = conn.client.get_ipintel()
    stix_objects = []

    conn.helper.connector_logger.info("[IP INTEL] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[IP INTEL] Creating observable",
            {"observable": entity.ip},
        )
        ip_obj = conn.converter_to_stix.create_obs(entity.ip)

        conn.helper.connector_logger.debug(
            "[IP INTEL] Creating infrastructure object of type command-and-control",
            {"c2_name": entity.matches[0]},
        )
        infra_obj = conn.converter_to_stix.create_infrastructure(
            name=entity.matches[0],
            infrastructure_type=INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL,
            last_seen=datetime.fromisoformat(entity.last_seen),
        )

        conn.helper.connector_logger.debug(
            "[IP INTEL] Creating location object",
            {"country_name": entity.country},
        )
        location_obj = conn.converter_to_stix.create_location(
            entity.country, entity.country_code
        )

        conn.helper.connector_logger.debug(
            '[IP INTEL] Creating "located-at" relationship',
        )
        infra_location_rel = conn.converter_to_stix.create_relationship(
            infra_obj.id, "located-at", location_obj.id
        )

        conn.helper.connector_logger.debug(
            '[IP INTEL] Creating "consists-of" relationship',
        )
        infra_ip_rel = conn.converter_to_stix.create_relationship(
            infra_obj.id, "consists-of", ip_obj.id
        )

        stix_objects.append(ip_obj)
        stix_objects.append(infra_obj)
        stix_objects.append(location_obj)

        stix_objects.append(infra_location_rel)
        stix_objects.append(infra_ip_rel)

    conn.helper.connector_logger.info("[IP INTEL] Data Source Completed!")
    return stix_objects
