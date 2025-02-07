import stix2
from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import INFRASTRUCTURE_TYPE_BOTNET
from vulncheck_sdk.models.advisory_botnet import AdvisoryBotnet

import vclib.util.works as works
from vclib.util.config import (
    SCOPE_INFRASTRUCTURE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)


def _create_infra(
    converter_to_stix, entity: AdvisoryBotnet, logger
) -> stix2.Infrastructure:
    logger.debug(
        "[BOTNET] Creating infrastructure of type botnet",
        {"botnet_name": entity.botnet_name},
    )
    return converter_to_stix.create_infrastructure(
        name=entity.botnet_name,
        infrastructure_type=INFRASTRUCTURE_TYPE_BOTNET,
    )


def _create_vuln(cve: str, converter_to_stix, logger) -> stix2.Vulnerability:
    logger.debug(
        "[BOTNET] Creating vulnerability",
        {"cve": cve},
    )
    return converter_to_stix.create_vulnerability(cve=cve)


def _create_rel_related_to(
    infrastructure: stix2.Infrastructure,
    vulnerability: stix2.Vulnerability,
    converter_to_stix,
    logger,
) -> stix2.Relationship:
    logger.debug(
        "[BOTNET] Creating related-to relationship",
    )
    return converter_to_stix.create_relationship(
        source_id=infrastructure["id"],
        relationship_type="related-to",
        target_id=vulnerability["id"],
    )


def _extract_stix_from_botnet(
    converter_to_stix, entities: list[AdvisoryBotnet], target_scope: list[str], logger
) -> list:
    result = []

    logger.info("[BOTNET] Parsing data into STIX objects")
    for entity in entities:
        infrastructure = None

        if SCOPE_INFRASTRUCTURE in target_scope and entity.botnet_name is not None:
            infrastructure = _create_infra(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            result.append(infrastructure)

        if SCOPE_VULNERABILITY in target_scope and entity.cve is not None:
            for cve in entity.cve:
                vuln = _create_vuln(
                    converter_to_stix=converter_to_stix,
                    cve=cve,
                    logger=logger,
                )
                result.append(vuln)
                if infrastructure is not None:
                    result.append(
                        _create_rel_related_to(
                            infrastructure=infrastructure,
                            vulnerability=vuln,
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                        )
                    )
    return result


def collect_botnets(
    config, helper: OpenCTIConnectorHelper, client, converter_to_stix, logger, _: dict
) -> None:
    # Check if data source is in scope for this run
    source_name = "Botnet"
    target_scope = [SCOPE_INFRASTRUCTURE, SCOPE_VULNERABILITY]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[BOTNET] Botnet is out of scope, skipping")
        return

    logger.info("[BOTNET] Starting collection")
    entities = client.get_botnets()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_botnet(
        converter_to_stix=converter_to_stix,
        entities=entities,
        target_scope=target_scope,
        logger=logger,
    )

    works.finish_work(
        helper=helper,
        logger=logger,
        stix_objects=stix_objects,
        work_id=work_id,
        work_name=source_name,
    )
    logger.info("[BOTNET] Data Source Completed!")
