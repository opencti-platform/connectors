from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import PATTERN_TYPE_SNORT

import vclib.util.works as works
from vclib.models.rule import Rule, RuleParser
from vclib.util.config import SCOPE_INDICATOR, compare_config_to_target_scope


def _extract_stix_from_snort(
    converter_to_stix, logger, snort_rules: list[Rule]
) -> list:
    logger.info("[SNORT] Parsing data into STIX objects")
    return [
        converter_to_stix.create_indicator(
            pattern=snort_rule.rule,
            pattern_type=PATTERN_TYPE_SNORT,
            name=snort_rule.name,
            description=snort_rule.description,
        )
        for snort_rule in snort_rules
    ]


def collect_snort(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    _: dict,
) -> None:
    # Check if data source is in scope for this run
    source_name = "Snort"
    target_scope = [SCOPE_INDICATOR]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[SNORT] Snort is out of scope, skipping")
        return

    logger.info("[SNORT] Starting collection")
    rule_string = client.get_rules("snort")

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_snort(
        converter_to_stix=converter_to_stix,
        snort_rules=RuleParser().parse(rule_string, logger),
        logger=logger,
    )

    works.finish_work(
        helper=helper,
        logger=logger,
        stix_objects=stix_objects,
        work_id=work_id,
        work_name=source_name,
    )
    logger.info("[SNORT] Data Source Completed!")
