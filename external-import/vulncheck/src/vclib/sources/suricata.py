from stix2.v21.vocab import PATTERN_TYPE_SURICATA

# from vclib.connector import ConnectorVulnCheck
from .util import RuleParser


def collect_suricata(conn, config_state: dict) -> list:
    """Collect all suricata rules

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[SURICATA] Starting collection")
    rule_string = conn.client.get_rules("suricata")

    conn.helper.connector_logger.info("[SURICATA] Parsing rules")
    rule_parser = RuleParser()
    snort_rules = rule_parser.parse(rule_string, conn.helper)

    stix_objects = []

    conn.helper.connector_logger.info("[SURICATA] Parsing data into STIX objects")
    for snort_rule in snort_rules:
        conn.helper.connector_logger.debug(
            "[SURICATA] Creating indicator object",
            {"rule_name": snort_rule.name},
        )
        indicator = conn.converter_to_stix.create_indicator(
            pattern=snort_rule.rule,
            pattern_type=PATTERN_TYPE_SURICATA,
            name=snort_rule.name,
            description=snort_rule.description,
        )
        stix_objects.append(indicator)

    conn.helper.connector_logger.info("[SURICATA] Data Source Completed!")
    return stix_objects
