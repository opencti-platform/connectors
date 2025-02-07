import stix2
import vclib.util.works as works
from pycti import OpenCTIConnectorHelper
from vclib.util.config import (
    SCOPE_SOFTWARE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vclib.util.cpe import parse_cpe_uri
from vulncheck_sdk.models.api_initial_access import ApiInitialAccess


def _create_vuln(
    converter_to_stix, entity: ApiInitialAccess, logger
) -> stix2.Vulnerability:
    logger.debug(
        "[INITIAL ACCESS] Creating vulnerability object",
        {"cve": entity.cve},
    )
    return converter_to_stix.create_vulnerability(
        cve=entity.cve,
        custom_properties={
            "x_opencti_cisa_kev": entity.in_kev,
        },
    )


def _create_software(converter_to_stix, logger, cpe: str) -> stix2.Software:
    cpe_dict = parse_cpe_uri(cpe)
    logger.debug(
        "[INITIAL ACCESS] Creating software object",
        {"software": cpe_dict["product"]},
    )
    return converter_to_stix.create_software(
        product=cpe_dict["product"],
        vendor=cpe_dict["vendor"],
        version=cpe_dict["version"],
        cpe=cpe,
    )


def _create_rel_has(
    software: stix2.Software,
    vulnerability: stix2.Vulnerability,
    converter_to_stix,
    logger,
):
    logger.debug(
        '[INITIAL ACCESS] Creating "has" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=software["id"],
        relationship_type="has",
        target_id=vulnerability["id"],
    )


def _extract_stix_from_initial_access(
    converter_to_stix, entities: list[ApiInitialAccess], target_scope: list[str], logger
) -> list:
    result = []
    logger.info("[INITIAL ACCESS] Parsing data into STIX objects")
    for entity in entities:
        vuln = None
        if SCOPE_VULNERABILITY in target_scope:
            vuln = _create_vuln(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            result.append(vuln)

        if SCOPE_SOFTWARE in target_scope and entity.vulnerable_cpes is not None:
            for cpe in entity.vulnerable_cpes:
                software = _create_software(
                    converter_to_stix=converter_to_stix,
                    cpe=cpe,
                    logger=logger,
                )
                result.append(software)

                if vuln is not None:
                    result.append(
                        _create_rel_has(
                            software=software,
                            vulnerability=vuln,
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                        )
                    )

    return result


def collect_initial_access(
    config, helper: OpenCTIConnectorHelper, client, converter_to_stix, logger, _: dict
) -> None:
    source_name = "Initial Access"
    target_scope = [SCOPE_VULNERABILITY, SCOPE_SOFTWARE]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )
    if target_scope == []:
        logger.info("[INITIAL ACCESS] Initial Access is out of scope, skipping")
        return

    logger.info("[INITIAL ACCESS] Starting collection")
    entities = client.get_initial_access()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_initial_access(
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
    logger.info("[INITIAL ACCESS] Data Source Completed!")
