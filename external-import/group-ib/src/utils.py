from datetime import datetime, timedelta

from config import ConfigConnector
from isodate import parse_duration
from pycti import OpenCTIConnectorHelper


class ExternalImportHelper:
    @staticmethod
    def validation_interval(
        cfg: ConfigConnector, helper: OpenCTIConnectorHelper
    ) -> str:
        """
        Validates the CONNECTOR__DURATION_PERIOD value to ensure it conforms to ISO-8601 duration format.
        """
        try:
            interval = cfg.connector_duration_period
            helper.log_info(
                f"Verifying integrity of the CONNECTOR__DURATION_PERIOD value: '{interval}'"
            )

            # Parse the ISO-8601 duration to ensure it is valid
            duration = parse_duration(interval)

            if not isinstance(duration, timedelta):
                raise ValueError("Parsed duration is not a valid timedelta object.")

            return interval  # Return the validated ISO-8601 duration string
        except Exception as ex:
            msg = (
                f"Error ({ex}) when grabbing CONNECTOR__DURATION_PERIOD environment variable: '{interval}'. "
                "It SHOULD be a valid ISO-8601 duration string (e.g., 'P7D', 'PT12H', 'PT10M', 'PT30S')."
            )
            helper.log_error(msg)
            raise ValueError(msg) from ex

    @staticmethod
    def get_interval(interval: str, helper: OpenCTIConnectorHelper) -> int:
        """
        Converts an ISO-8601 duration string to seconds.

        This always returns the interval in seconds for the connector.
        """
        try:
            # Parse the ISO-8601 duration and convert to timedelta
            duration = parse_duration(interval)

            if not isinstance(duration, timedelta):
                raise ValueError("Parsed duration is not a valid timedelta object.")

            # Convert timedelta to seconds
            return int(duration.total_seconds())
        except Exception as ex:
            helper.log_error(
                f"Error when converting CONNECTOR__DURATION_PERIOD environment variable: '{interval}'. {str(ex)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR__DURATION_PERIOD environment variable: '{interval}'. {str(ex)}"
            ) from ex

    def validation_update_existing_data(
        cfg: ConfigConnector, helper: OpenCTIConnectorHelper
    ) -> str | bool:
        update_existing_data = cfg.connector_update_existing_data
        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            update_existing_data = update_existing_data.lower() == "true"
        elif isinstance(update_existing_data, bool) and update_existing_data in [
            True,
            False,
        ]:
            update_existing_data = update_existing_data
        else:
            msg = (
                f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. "
                "It SHOULD be either `true` or `false`. `false` is assumed. "
            )
            helper.log_warning(msg)
            update_existing_data = "false"

        return update_existing_data

    def get_next_run_it(
        interval: str, helper: OpenCTIConnectorHelper, timestamp: int, last_run: int
    ):
        last_run = 0 if last_run is None else last_run
        new_interval = ExternalImportHelper.get_interval(
            interval=interval, helper=helper
        ) - (timestamp - last_run)
        return datetime.now() + timedelta(seconds=new_interval)
