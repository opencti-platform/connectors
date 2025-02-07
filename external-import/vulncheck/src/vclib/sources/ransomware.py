import stix2
import vclib.util.works as works
from pycti import OpenCTIConnectorHelper
from vclib.util.config import (
    SCOPE_MALWARE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vulncheck_sdk.models.advisory_ransomware_exploit import AdvisoryRansomwareExploit


def _create_malware(
    converter_to_stix, entity: AdvisoryRansomwareExploit, logger
) -> stix2.Malware:
    logger.debug(
        "[RANSOMWARE] Creating malware object",
        {"ransomware_name": entity.ransomware_family},
    )
    return converter_to_stix.create_malware(
        name=entity.ransomware_family,
        is_family=True,
        first_seen=entity.date_added,
    )


def _create_vuln(converter_to_stix, cve: str, logger) -> stix2.Vulnerability:
    logger.debug(
        "[RANSOMWARE] Creating vulnerability object",
        {"cve": cve},
    )
    return converter_to_stix.create_vulnerability(cve=cve)


def _create_rel_exploits(
    malware: stix2.Malware,
    vulnerability: stix2.Vulnerability,
    converter_to_stix,
    logger,
) -> stix2.Relationship:
    logger.debug(
        '[RANSOMWARE] Creating "exploits" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=malware["id"],
        relationship_type="exploits",
        target_id=vulnerability["id"],
    )


def _extract_stix_from_ransomware(
    converter_to_stix,
    entities: list[AdvisoryRansomwareExploit],
    target_scope: list[str],
    logger,
) -> list:
    result = []

    logger.info("[RANSOMWARE] Parsing data into STIX objects")
    for entity in entities:
        malware = None

        if SCOPE_MALWARE in target_scope:
            malware = _create_malware(converter_to_stix, entity, logger)
            result.append(malware)

        if SCOPE_VULNERABILITY and entity.cve is not None:
            for cve in entity.cve:
                vuln = _create_vuln(
                    converter_to_stix=converter_to_stix,
                    cve=cve,
                    logger=logger,
                )
                result.append(vuln)
                if malware is not None:
                    result.append(
                        _create_rel_exploits(
                            malware=malware,
                            vulnerability=vuln,
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                        )
                    )
    return result


def collect_ransomware(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    _: dict,
) -> None:
    source_name = "Ransomware"
    target_scope = [SCOPE_VULNERABILITY, SCOPE_MALWARE]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[RANSOMWARE] Ransomware is out of scope, skipping")
        return

    logger.info("[RANSOMWARE] Starting collection")
    entities = client.get_ransomware()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_ransomware(
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
    logger.info("[RANSOMWARE] Data Source Completed!")
