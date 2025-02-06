from datetime import timedelta
from typing import Annotated, Literal

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)

AnyUrlToString = Annotated[AnyUrl, PlainSerializer(str, return_type=str)]


class ProofpointEtIntelligenceConfigVar(BaseModel):
    """ConfigurationVar model for the ProofPoint ET Intelligence connector.

    This class defines the configuration variables required by the ProofPoint ET Intelligence connector.
    It uses Pydantic's BaseModel for validation and provides metadata for each field.

    Attributes:
        model_config (ConfigDict): Automatic trimming of whitespace and enforcement of minimum length for string fields.

        opencti_url (AnyUrl): The OpenCTI platform URL.
        opencti_token (str): The API token for authentication to the OpenCTI platform.

        connector_id (str): A unique identifier for the OpenCTI connector.
        connector_type (Literal): Specifies the type of the connector. Allowed values are:
            "EXTERNAL_IMPORT", "INTERNAL_ENRICHMENT", "INTERNAL_EXPORT_FILE", "INTERNAL_IMPORT_FILE", "STREAM"
        connector_name (str): The name of the connector as it will appear in OpenCTI.
        connector_scope (str): A comma-separated list of scopes.
            Input is case-insensitive; output is standardized to the specified format.
            Allowed values are: "IPv4-Addr", "Domain-Name", "StixFile"
        connector_log_level (Literal): The log level for the connector.
            Allowed values are: "debug", "info", "warn", "error"
        connector_auto (bool): Enable or disable automatic enrichment of observables for OpenCTI.

        extra_api_key (str): The API key used for accessing ProofPoint ET Intelligence.
        extra_api_base_url (HttpUrl): The base URL of the ProofPoint ET Intelligence API.
        extra_max_tlp (Literal): Maximum TLP (Traffic Light Protocol) level the connector can enrich.
            Allowed values are: "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"
        extra_import_last_seen_time_window (timedelta): Specifies the time window for importing 'last_seen' data in
            ISO 8601 format.

    Methods:
        validate_scope(cls, value: str) -> str:
            Validates the `connector_scope` field.
            - Accepts case-insensitive input.
            - Ensures that values are valid. Standardizes output to the expected format.
    """

    # Model configurations
    model_config = ConfigDict(str_strip_whitespace=True, str_min_length=1)

    # OpenCTI configurations
    opencti_url: AnyUrlToString = Field(..., description="The OpenCTI platform URL.")
    opencti_token: str = Field(
        ..., description="The API token for authentication to the OpenCTI platform."
    )

    # Connector configurations
    connector_id: str = Field(
        ..., description="A unique identifier for the OpenCTI connector."
    )
    connector_type: Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ] = Field(
        ...,
        description="The type of the connector. Allowed values are: "
        "EXTERNAL_IMPORT, INTERNAL_ENRICHMENT, INTERNAL_EXPORT_FILE, INTERNAL_IMPORT_FILE, STREAM.",
        examples=[
            "EXTERNAL_IMPORT",
            "INTERNAL_ENRICHMENT",
            "INTERNAL_EXPORT_FILE",
            "INTERNAL_IMPORT_FILE",
            "STREAM",
        ],
    )
    connector_name: str = Field(
        ..., description="The name of the connector as it will appear in OpenCTI."
    )
    connector_scope: str = Field(
        ...,
        description="List of scopes for the connector. Allowed values are 'IPv4-Addr', 'Domain-Name', 'StixFile'.",
        examples=["IPv4-Addr", "Domain-Name", "StixFile"],
    )
    connector_log_level: Literal["debug", "info", "warn", "error"] = Field(
        ...,
        description="The log level for the connector. Allowed values are 'debug', 'info', 'warn', or 'error'.",
        examples=["debug", "info", "warn", "error"],
    )
    connector_auto: bool = Field(
        ...,
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
    )

    # ProofPoint ET Intelligence Extra parameters
    extra_api_key: str = Field(
        ...,
        description="The API key used for authentication to access the API ProofPoint ET Intelligence.",
    )
    extra_api_base_url: HttpUrl = Field(
        ..., description="The base URL used to connect to the API endpoint."
    )
    extra_max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        ...,
        description="The maximum TLP (Traffic Light Protocol) level the connector is authorized to enrich. "
        "Allowed values are: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED.",
        examples=[
            "TLP:CLEAR",
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ],
    )
    extra_import_last_seen_time_window: timedelta = Field(
        ...,
        description="The time window for importing 'last_seen' data, specified in ISO 8601 duration format.",
        examples=["PT24H", "P1D", "P1DT12H"],
    )

    @field_validator("connector_scope", mode="after")
    def validate_scope(cls, value: str) -> str:
        """Validates and formats the `connector_scope` field.

        This method takes the connector_scope string as input, checks that all specified scopes are valid against a predefined list of allowed scopes.
        It normalises the input to ensure a standardised format (case-insensitive) and returns a comma-separated string of valid scopes.
        If some scopes are invalid, only valid scopes are retained in the result. If no valid scopes are found, an error is raised.

        Args:
            value (str): A comma-separated string containing one or more scope values to be validated.

        Returns:
            str: A comma-separated string of valid and standardised scope values.

        Raises:
            ValueError: If no valid scopes are found in the input value, a `ValueError` is raised, detailing the allowed values.

        Example:
            If `value = "IPv4-Addr, domain-name, stixfile"`, the method will return
            "IPv4-Addr,Domain-Name,StixFile" as the output.

        Notes:
            The method uses the following available values for validation:
            - "ipv4-addr" -> "IPv4-Addr"
            - "domain-name" -> "Domain-Name"
            - "stixfile" -> "StixFile"

            The input values are case-insensitive and the output will always follow the specified format (with the correct case for each scope).
            In addition, the output will not include spaces after the commas separating the scopes.
        """
        available_values = {
            "ipv4-addr": "IPv4-Addr",
            "domain-name": "Domain-Name",
            "stixfile": "StixFile",
        }
        scope_splitted = [scope.strip().lower() for scope in value.split(",")]
        valid_scope = [
            available_values[scope]
            for scope in scope_splitted
            if scope in available_values
        ]

        if not valid_scope:
            raise ValueError(
                f"No valid scopes found. Allowed values are: {available_values}."
            )
        scope_string = ",".join(valid_scope)

        return scope_string
