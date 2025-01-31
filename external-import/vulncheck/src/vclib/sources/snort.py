from stix2.v21.vocab import PATTERN_TYPE_SNORT

# from vclib.connector import ConnectorVulnCheck
from .util import RuleParser


def collect_snort(conn, config_state: dict) -> list:
    """Collect all snort rules

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[SNORT] Starting collection")
    rule_string = conn.client.get_rules("snort")

    conn.helper.connector_logger.info("[SNORT] Parsing rules")
    rule_parser = RuleParser()
    snort_rules = rule_parser.parse(rule_string, conn.helper)

    stix_objects = []

    conn.helper.connector_logger.info("[SNORT] Parsing data into STIX objects")
    for snort_rule in snort_rules:
        conn.helper.connector_logger.debug(
            "[SNORT] Creating indicator object",
            {"rule_name": snort_rule.name},
        )
        indicator = conn.converter_to_stix.create_indicator(
            pattern=snort_rule.rule,
            pattern_type=PATTERN_TYPE_SNORT,
            name=snort_rule.name,
            description=snort_rule.description,
        )
        stix_objects.append(indicator)

    conn.helper.connector_logger.info("[SNORT] Data Source Completed!")
    return stix_objects
