from datetime import datetime

import stix2
from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL
from vulncheck_sdk.models.advisory_ip_intel_record import AdvisoryIpIntelRecord

import vclib.util.works as works
from vclib.util.config import (
    SCOPE_INFRASTRUCTURE,
    SCOPE_IP,
    SCOPE_LOCATION,
    compare_config_to_target_scope,
)


def _create_ip(converter_to_stix, entity: AdvisoryIpIntelRecord, logger):
    logger.debug(
        "[IP INTEL] Creating observable",
        {"observable": entity.ip},
    )
    return converter_to_stix.create_obs(value=entity.ip)


def _create_infra(
    converter_to_stix, entity: AdvisoryIpIntelRecord, logger
) -> stix2.Infrastructure:
    logger.debug(
        "[IP INTEL] Creating infrastructure object of type command-and-control",
        {"c2_name": entity.matches[0]},
    )
    return converter_to_stix.create_infrastructure(
        name=entity.matches[0],
        infrastructure_type=INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL,
        last_seen=datetime.fromisoformat(entity.last_seen),
    )


def _create_location(
    converter_to_stix, entity: AdvisoryIpIntelRecord, logger
) -> stix2.Location:
    logger.debug(
        "[IP INTEL] Creating location object",
        {"country_name": entity.country},
    )
    return converter_to_stix.create_location(
        country_name=entity.country, country_code=entity.country_code
    )


def _create_rel_located_at(
    converter_to_stix, infra: stix2.Infrastructure, location: stix2.Location, logger
) -> stix2.Relationship:
    logger.debug(
        '[IP INTEL] Creating "located-at" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=infra.id, relationship_type="located-at", target_id=location.id
    )


def _create_rel_consists_of(
    converter_to_stix, infra: stix2.Infrastructure, ip, logger
) -> stix2.Relationship:
    logger.debug(
        '[IP INTEL] Creating "consists-of" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=infra.id, relationship_type="consists-of", target_id=ip.id
    )


def _extract_stix_from_ipintel(
    converter_to_stix,
    entities: list[AdvisoryIpIntelRecord],
    target_scope: list[str],
    logger,
) -> list:
    result = []

    logger.info("[IP INTEL] Parsing data into STIX objects")
    for entity in entities:
        ip = None
        infra = None
        location = None

        if SCOPE_IP in target_scope:
            ip = _create_ip(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            result.append(ip)
        if SCOPE_INFRASTRUCTURE in target_scope:
            infra = _create_infra(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            result.append(infra)
        if SCOPE_LOCATION in target_scope:
            location = _create_location(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            result.append(location)

        if infra is not None and location is not None:
            result.append(
                _create_rel_located_at(
                    converter_to_stix=converter_to_stix,
                    infra=infra,
                    location=location,
                    logger=logger,
                )
            )
        if infra is not None and ip is not None:
            result.append(
                _create_rel_consists_of(
                    converter_to_stix=converter_to_stix,
                    infra=infra,
                    ip=ip,
                    logger=logger,
                )
            )

    return result


def collect_ipintel(
    config, helper: OpenCTIConnectorHelper, client, converter_to_stix, logger, _: dict
) -> None:
    source_name = "IP Intel"
    target_scope = [SCOPE_IP, SCOPE_INFRASTRUCTURE, SCOPE_LOCATION]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[IP INTEL] IP Intel is out of scope, skipping")
        return

    logger.info("[IP INTEL] Starting collection")
    entities = client.get_ipintel()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_ipintel(
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
    logger.info("[IP INTEL] Data Source Completed!")
