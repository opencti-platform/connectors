from datetime import datetime
from enum import Enum

import pycountry


class DateTimeFormat(Enum):
    DATETIME = "datetime"  # Object datetime
    ISO = "iso"  # Format ISO 8601
    TIMESTAMP = "timestamp"  #  Unix Timestamp


class Utils:

    @staticmethod
    def get_now(now_format: DateTimeFormat = None) -> datetime | str | int | dict:
        """Utility method: Get the current date and time in various formats.
        Parameters:
            now_format (DateTimeFormat, None) :
            The desired format for the current date and time. Possible values are:
            - DateTimeFormat.DATETIME: Return a `datetime` object representing the current date and time.
            - DateTimeFormat.ISO: Return the current date and time as an ISO 8601 formatted string.
            - DateTimeFormat.TIMESTAMP: Return the current time as a UNIX timestamp (seconds since epoch).
            - None (default): If no format is specified, returns a dictionary containing all the formats.
        Returns:
            datetime, str, int, or dict :
            - If `now_format` is DateTimeFormat.DATETIME, return a `datetime` object.
            - If `now_format` is DateTimeFormat.ISO, return an ISO 8601 formatted string.
            - If `now_format` is DateTimeFormat.TIMESTAMP, return an integer UNIX Timestamp.
            - If `now_format` is None (default), returns a dictionary with the following keys:
                - "now_datetime": The current `datetime` object.
                - "now_isoformat": The current date and time as an ISO 8601 formatted string.
                - "now_timestamp": The current time as a UNIX Timestamp.
        Examples:
            >> get_now(DateTimeFormat.DATETIME) = datetime(2025, 1, 1, 0, 0, 0)
            >> get_now(DateTimeFormat.ISO) = '2025-01-01 00:00:00'
            >> get_now(DateTimeFormat.TIMESTAMP) = 1735689600
            >> get_now() =
            {
            "now_datetime": datetime(2025, 1, 1, 0, 0, 0),
            "now_isoformat": "2025-01-01 00:00:00",
            "now_timestamp": 1735689600,
            }
        """
        now = datetime.now()
        if now_format == DateTimeFormat.DATETIME:
            return now
        elif now_format == DateTimeFormat.ISO:
            return now.isoformat(sep=" ", timespec="seconds")
        elif now_format == DateTimeFormat.TIMESTAMP:
            return int(datetime.timestamp(now))
        else:
            now_isoformat = now.isoformat(sep=" ", timespec="seconds")
            now_timestamp = int(datetime.timestamp(now))
            return {
                "now_datetime": now,
                "now_isoformat": now_isoformat,
                "now_timestamp": now_timestamp,
            }

    @staticmethod
    def get_location_info(geolocation: dict) -> dict:
        """This method allows you to retrieve the official name of the country based only on the country code.

        Args:
            geolocation:

        Returns: dict

        """
        country_code = geolocation.get("country_code")
        country_info = pycountry.countries.get(alpha_2=country_code)

        # If possible get official country name and update country name
        if hasattr(country_info, "official_name"):
            country_name = country_info.official_name
        else:
            country_name = geolocation.get("country", country_info.name)
        geolocation["country"] = country_name

        # If possible update region name
        region = geolocation.get("region")
        region_name = None
        if region:
            subdivision = pycountry.subdivisions.get(code=f"{country_code}-{region}")
            region_name = (
                subdivision.name
                if subdivision and hasattr(subdivision, "name")
                else region
            )

        geolocation["region"] = region_name
        return geolocation
