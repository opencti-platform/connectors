from datetime import datetime

from pycti import OpenCTIConnectorHelper


def start_work(helper: OpenCTIConnectorHelper, logger, work_name, work_num=None):
    logger.info(
        "[WORKS] Starting new work...",
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"VulnCheck {work_name} run @{now}"
    if work_num is not None:
        message = f"VulnCheck {work_name} run {work_num} @{now}"
    id = helper.api.work.initiate_work(helper.connect_id, message)
    return id


def finish_work(
    helper: OpenCTIConnectorHelper,
    logger,
    stix_objects,
    work_id,
    work_name,
    work_num=None,
):
    logger.debug(
        "[WORKS] Bundling objects",
    )
    stix_objects_bundle = helper.stix2_create_bundle(stix_objects)
    logger.info(
        "[WORKS] Preparing to send bundle",
    )
    if stix_objects_bundle is not None:
        bundles_sent = helper.send_stix2_bundle(stix_objects_bundle, work_id=work_id)
        logger.info(
            "[WORKS] Sending STIX objects to OpenCTI...",
            {"bundles_sent": {str(len(bundles_sent))}},
        )

    message = (
        f"[WORKS] Run {work_name}-{work_num} completed"
        if work_num is not None
        else f"[WORKS] Run {work_name} completed"
    )

    helper.api.work.to_processed(work_id, message)
    logger.info(message)
