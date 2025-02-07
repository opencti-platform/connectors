from datetime import datetime

import stix2
from pycti import OpenCTIConnectorHelper
from vulncheck_sdk.models.advisory_cve_reference import AdvisoryCVEReference
from vulncheck_sdk.models.advisory_threat_actor_with_external_objects import (
    AdvisoryThreatActorWithExternalObjects,
)

import vclib.util.works as works
from vclib.util.config import (
    SCOPE_EXTERNAL_REF,
    SCOPE_THREAT_ACTOR,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)


def _create_external_ref(
    converter_to_stix, logger, reference: AdvisoryCVEReference
) -> stix2.ExternalReference:
    logger.debug(
        "[THREAT ACTORS] Creating external reference",
        {"ref_url": reference.url},
    )
    return converter_to_stix.create_external_reference(reference.url, reference.url)


def _create_vulns(converter_to_stix, logger, vulnerabilities: list[str]) -> list:
    logger.debug(
        "[THREAT ACTORS] Creating vulnerabilities",
    )
    return [converter_to_stix.create_vulnerability(cve=cve) for cve in vulnerabilities]


def _create_threat_actor(
    converter_to_stix,
    entity: AdvisoryThreatActorWithExternalObjects,
    logger,
    external_refs: list[stix2.ExternalReference],
) -> stix2.ThreatActor:
    logger.debug(
        "[THREAT ACTORS] Creating threat actor group",
        {"threat_actor": entity.threat_actor_name},
    )
    return converter_to_stix.create_threat_actor_group(
        name=entity.threat_actor_name,
        first_seen=datetime.fromisoformat(entity.date_added),
        external_refs=external_refs,
    )


def _create_rel_targets(
    threat_actor: stix2.ThreatActor,
    vulnerability: stix2.Vulnerability,
    converter_to_stix,
    logger,
) -> stix2.Relationship:
    logger.debug(
        '[THREAT ACTORS] Creating "targets" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=threat_actor["id"],
        relationship_type="targets",
        target_id=vulnerability["id"],
    )


def _extract_cve_references(
    cve_references: list[AdvisoryCVEReference] | None,
    target_scope: list[str],
    converter_to_stix,
    logger,
) -> tuple[list[stix2.ExternalReference], list[stix2.Vulnerability]]:
    vulnerabilities = []
    external_refs = []
    if (
        SCOPE_EXTERNAL_REF in target_scope or SCOPE_VULNERABILITY in target_scope
    ) and cve_references is not None:
        for reference in cve_references:
            if SCOPE_EXTERNAL_REF in target_scope:
                external_refs.append(
                    _create_external_ref(
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                        reference=reference,
                    )
                )
            if SCOPE_VULNERABILITY in target_scope and reference.cve is not None:
                vulnerabilities = _create_vulns(
                    converter_to_stix=converter_to_stix,
                    logger=logger,
                    vulnerabilities=reference.cve,
                )
    return external_refs, vulnerabilities


def _extract_threat_actors(
    entity: AdvisoryThreatActorWithExternalObjects,
    external_refs: list[stix2.ExternalReference],
    vulnerabilities: list[stix2.Vulnerability],
    target_scope: list[str],
    converter_to_stix,
    logger,
) -> list:
    result = []
    if SCOPE_THREAT_ACTOR in target_scope:
        threat_actor = _create_threat_actor(
            converter_to_stix=converter_to_stix,
            entity=entity,
            logger=logger,
            external_refs=external_refs,
        )
        result.append(threat_actor)
        if vulnerabilities != []:
            result.extend(
                [
                    _create_rel_targets(
                        threat_actor=threat_actor,
                        vulnerability=vulnerability,
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                    )
                    for vulnerability in vulnerabilities
                ]
            )
    return result


def _extract_stix_from_threat_actors(
    entities: list[AdvisoryThreatActorWithExternalObjects],
    target_scope: list[str],
    converter_to_stix,
    logger,
) -> list:
    stix_objects = []
    logger.info("[THREAT ACTORS] Parsing data into STIX objects")
    for entity in entities:
        # NOTE: We need these refs when creating the threat actor
        external_refs, vulnerabilities = _extract_cve_references(
            cve_references=entity.cve_references,
            target_scope=target_scope,
            converter_to_stix=converter_to_stix,
            logger=logger,
        )

        stix_objects.extend(
            _extract_threat_actors(
                entity=entity,
                external_refs=external_refs,
                vulnerabilities=vulnerabilities,
                target_scope=target_scope,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )
    return stix_objects


def collect_threat_actors(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    _: dict,
) -> None:
    # Check if data source is in scope for this run
    source_name = "Threat Actors"
    target_scope = [SCOPE_THREAT_ACTOR, SCOPE_VULNERABILITY, SCOPE_EXTERNAL_REF]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[THREAT ACTORS] Threat Actors is out of scope, skipping")
        return

    logger.info("[THREAT ACTORS] Starting collection")
    entities = client.get_threat_actors()

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_threat_actors(
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
    logger.info("[THREAT ACTORS] Data Source Completed!")
