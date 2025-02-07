from typing import Tuple

SCOPE_VULNERABILITY = "vulnerability"
SCOPE_MALWARE = "malware"
SCOPE_THREAT_ACTOR = "threat-actor"
SCOPE_SOFTWARE = "software"
SCOPE_INFRASTRUCTURE = "infrastructure"
SCOPE_LOCATION = "location"
SCOPE_IP = "ip-addr"
SCOPE_INDICATOR = "indicator"
SCOPE_EXTERNAL_REF = "external-reference"


def compare_config_to_target_scope(
    config, target_scope: list[str], name: str, logger
) -> list[str]:
    logger.info(f"[{name}] Checking scope")
    configured_scope = _get_configured_scope(config)
    intersection = get_intersection_of_string_lists(configured_scope, target_scope)
    if intersection == []:
        logger.info(
            f"[{name}] Configured scope does not include data sources target scope"
        )
    else:
        logger.info(
            f"[{name}] Source is in scope!", {"intersection_of_scope": intersection}
        )
    return intersection


def get_time_until_next_run(
    current_timestamp: int, last_run_timestamp: int
) -> Tuple[int, int]:
    time_diff = current_timestamp - last_run_timestamp
    if time_diff < 24 * 3600:
        remaining_time = 24 * 3600 - time_diff
        hours, remainder = divmod(remaining_time, 3600)
        minutes, _ = divmod(remainder, 60)
        return hours, minutes
    return 0, 0


def get_intersection_of_string_lists(a: list[str], b: list[str]) -> list[str]:
    return list(set(a) & set(b))


def get_configured_sources(config) -> list[str]:
    return config.data_sources.split(",")


def _get_configured_scope(config) -> list[str]:
    return config.scope.split(",")
