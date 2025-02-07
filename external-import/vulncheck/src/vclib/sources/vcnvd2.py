import json
import os
import zipfile

import stix2
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError
from vulncheck_sdk.models.api_nvd20_cve_extended import ApiNVD20CVEExtended

import vclib.util.works as works
from vclib.models import data_source
from vclib.util.config import (
    SCOPE_SOFTWARE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vclib.util.cpe import parse_cpe_uri
from vclib.util.memory_usage import log_memory_usage
from vclib.util.nvd import check_size_of_stix_objects, check_vuln_description


def _create_vuln(
    entity: ApiNVD20CVEExtended, converter_to_stix, logger
) -> stix2.Vulnerability:
    logger.debug(
        "[VULNCHECK NVD-2] Creating vulnerability object",
        {"cve": entity.id},
    )
    description = (
        check_vuln_description(descriptions=entity.descriptions)
        if entity.descriptions is not None
        else ""
    )
    if entity.metrics is not None and entity.metrics.cvss_metric_v31 is not None:
        cvss_data = entity.metrics.cvss_metric_v31[0].cvss_data
        return converter_to_stix.create_vulnerability(
            cve=entity.id,
            description=description,
            custom_properties={
                "x_opencti_cvss_base_score": cvss_data.base_score,
                "x_opencti_cvss_base_severity": cvss_data.base_severity,
                "x_opencti_cvss_attack_vector": cvss_data.attack_vector,
            },
        )
    elif entity.metrics is not None and entity.metrics.cvss_metric_v30 is not None:
        cvss_data = entity.metrics.cvss_metric_v30[0].cvss_data
        return converter_to_stix.create_vulnerability(
            cve=entity.id,
            description=description,
            custom_properties={
                "x_opencti_cvss_base_score": cvss_data.base_score,
                "x_opencti_cvss_base_severity": cvss_data.base_severity,
                "x_opencti_cvss_attack_vector": cvss_data.attack_vector,
            },
        )
    else:
        return converter_to_stix.create_vulnerability(
            cve=entity.id,
            description=description,
        )


def _create_software(cpe: str, converter_to_stix, logger) -> stix2.Software:
    cpe_dict = parse_cpe_uri(cpe)
    logger.debug(
        "[VULNCHECK NVD-2] Creating software object",
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
) -> stix2.Relationship:
    logger.debug(
        '[NIST NVD-2] Creating "has" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=software["id"],
        relationship_type="has",
        target_id=vulnerability["id"],
    )


def _extract_stix_from_vcnvd2(
    entity: ApiNVD20CVEExtended, target_scope: list[str], converter_to_stix, logger
) -> list:
    result = []
    vuln = None

    if SCOPE_VULNERABILITY in target_scope:
        vuln = _create_vuln(
            entity=entity, converter_to_stix=converter_to_stix, logger=logger
        )
        result.append(vuln)

    if SCOPE_SOFTWARE in target_scope and entity.vc_vulnerable_cpes is not None:
        for cpe in entity.vc_vulnerable_cpes:
            software = _create_software(
                cpe=cpe, converter_to_stix=converter_to_stix, logger=logger
            )
            if vuln is not None:
                result.extend(
                    _create_rel_has(
                        software=software,
                        vulnerability=vuln,
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                    )
                )
    return result


def _process_vc_nvd2_json(
    converter_to_stix,
    logger,
    target_scope: list[str],
    data,
) -> list:
    result = []
    for item in data["results"]:
        try:
            entity = ApiNVD20CVEExtended.model_validate(item)
        except ValidationError as e:
            logger.error(
                f"Unable to validate JSON for NIST-NVD2 object, {e}",
                {"item": item},
            )
            continue
        log_memory_usage(logger)
        result.extend(
            _extract_stix_from_vcnvd2(
                entity=entity,
                target_scope=target_scope,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )
    return result


def _collect_vc_nvd2_from_backup(
    filepath: str,
    target_scope: list[str],
    helper,
    converter_to_stix,
    logger,
    source_name: str,
    cleanup=True,
) -> None:
    work_num = 1

    # Initiate new work
    work_id = works.start_work(
        helper=helper,
        logger=logger,
        work_name=source_name,
        work_num=work_num,
    )
    stix_objects = []

    logger.info("[VULNCHECK NVD-2] Parsing data into STIX objects")

    with zipfile.ZipFile(filepath, "r") as zip_ref:
        for file_name in zip_ref.namelist():
            if file_name.endswith(".json"):
                with zip_ref.open(file_name) as json_file:
                    stix_objects.extend(
                        _process_vc_nvd2_json(
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                            target_scope=target_scope,
                            data=json.load(json_file),
                        )
                    )

                    stix_objects, work_id, work_num = check_size_of_stix_objects(
                        helper=helper,
                        logger=logger,
                        source_name=source_name,
                        stix_objects=stix_objects,
                        target_scope=target_scope,
                        work_id=work_id,
                        work_num=work_num,
                    )

    if len(stix_objects) > 0:
        works.finish_work(
            helper=helper,
            logger=logger,
            stix_objects=stix_objects,
            work_id=work_id,
            work_name=source_name,
            work_num=work_num,
        )
    logger.info(
        "Finished parsing STIX from VulnCheck-NVD2 backup!",
    )
    if cleanup:
        os.remove(filepath)


def _collect_vc_nvd2_from_api(
    entities: list[ApiNVD20CVEExtended],
    target_scope: list[str],
    helper,
    converter_to_stix,
    logger,
    source_name: str,
) -> None:
    stix_objects = []

    total = len(entities)

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    logger.info("[VULNCHECK NVD-2] Parsing data into STIX objects")

    for i, entity in enumerate(entities):
        logger.info(f"[VULNCHECK NVD-2] Entity {i}/{total}: {entity.id}")

        stix_objects.extend(
            _extract_stix_from_vcnvd2(
                converter_to_stix=converter_to_stix,
                entity=entity,
                logger=logger,
                target_scope=target_scope,
            )
        )

    works.finish_work(
        helper=helper,
        logger=logger,
        stix_objects=stix_objects,
        work_id=work_id,
        work_name=source_name,
    )


def collect_vcnvd2(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    connector_state: dict,
) -> None:
    source_name = "VulnCheck NVD-2"
    target_scope = [SCOPE_VULNERABILITY, SCOPE_SOFTWARE]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[VULNCHECK NVD-2] VulnCheck NVD-2 is out of scope, skipping")
        return

    logger.info("[VULNCHECK NVD-2] Starting collection")

    if connector_state is not None and data_source.VULNCHECK_NVD2 in connector_state:
        _collect_vc_nvd2_from_api(
            entities=client.get_vcnvd2(),
            target_scope=target_scope,
            helper=helper,
            converter_to_stix=converter_to_stix,
            logger=logger,
            source_name=source_name,
        )
    else:
        _collect_vc_nvd2_from_backup(
            filepath=client.get_vcnvd2_backup_filepath(),
            target_scope=target_scope,
            helper=helper,
            converter_to_stix=converter_to_stix,
            logger=logger,
            source_name=source_name,
        )

    logger.info("[VULNCHECK NVD-2] Data Source Completed!")
