import stix2
from pycti import OpenCTIConnectorHelper
from vulncheck_sdk.models.api_epss_data import ApiEPSSData

import vclib.util.works as works
from vclib.util.config import SCOPE_VULNERABILITY, compare_config_to_target_scope


def _create_vuln(converter_to_stix, entity: ApiEPSSData, logger) -> stix2.Vulnerability:
    logger.debug(
        "[EPSS] Creating vulnerability",
        {"cve": entity.cve},
    )
    return converter_to_stix.create_vulnerability(
        cve=entity.cve,
        custom_properties={
            "x_opencti_epss_score": entity.epss_score,
            "x_opencti_epss_percentile": entity.epss_percentile,
        },
    )


def _extract_stix_from_epss(
    converter_to_stix, entities: list[ApiEPSSData], logger
) -> list:
    logger.info("[EPSS] Parsing data into STIX objects")
    return [
        _create_vuln(converter_to_stix=converter_to_stix, entity=e, logger=logger)
        for e in entities
    ]


def collect_epss(
    config, helper: OpenCTIConnectorHelper, client, converter_to_stix, logger, _: dict
) -> None:
    source_name = "EPSS"
    target_scope = [SCOPE_VULNERABILITY]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name,
        logger=logger,
    )

    if target_scope == []:
        logger.info("[EPSS] EPSS is out of scope, skipping")
        return

    logger.info("[EPSS] Starting collection")
    entities = client.get_epss()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)
    stix_objects = _extract_stix_from_epss(
        converter_to_stix=converter_to_stix,
        entities=entities,
        logger=logger,
    )

    works.finish_work(
        helper=helper,
        logger=logger,
        stix_objects=stix_objects,
        work_id=work_id,
        work_name=source_name,
    )
    logger.info("[EPSS] Data Source Completed!")
