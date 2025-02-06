from pathlib import Path

import yaml
from connector.models import ProofpointEtIntelligenceConfigVar
from pycti import get_config_variable
from pydantic import ValidationError


class ProofpointEtIntelligenceConfig:
    def __init__(self):
        """Load configuration file"""
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """Load the configuration from the YAML file

        Returns: Configuration dictionary
        """

        config_file_path = Path(__file__).parents[2] / "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        # We force the variable to be here INTERNAL_ENRICHMENT
        config.setdefault("connector", {}).update({"type": "INTERNAL_ENRICHMENT"})
        return config

    def _initialize_configurations(self) -> None:
        """Connector configuration variables"""

        # OpenCTI configurations
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], self.load, required=True
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], self.load, required=True
        )

        # Connector configurations
        self.connector_id = get_config_variable(
            "CONNECTOR_ID",
            ["connector", "id"],
            self.load,
            required=True,
        )
        self.connector_type = get_config_variable(
            "CONNECTOR_TYPE",
            ["connector", "type"],
            self.load,
            default="INTERNAL_ENRICHMENT",
        )
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load,
            default="ProofPoint ET Intelligence",
        )
        self.connector_scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            self.load,
            default="IPv4-Addr,Domain-Name,StixFile",
        )
        self.connector_log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            self.load,
            default="error",
        )
        self.connector_auto = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "auto"],
            self.load,
            default=True,
        )

        # ProofPoint ET Intelligence extra parameters
        self.extra_api_base_url = get_config_variable(
            "PROOFPOINT_ET_INTELLIGENCE_API_BASE_URL",
            ["proofpoint_et_intelligence", "api_base_url"],
            self.load,
            default="https://api.emergingthreats.net/v1/",
        )
        self.extra_api_key = get_config_variable(
            "PROOFPOINT_ET_INTELLIGENCE_API_KEY",
            ["proofpoint_et_intelligence", "api_key"],
            self.load,
            required=True,
        )
        self.extra_max_tlp = get_config_variable(
            "PROOFPOINT_ET_INTELLIGENCE_MAX_TLP",
            ["proofpoint_et_intelligence", "max_tlp"],
            self.load,
            default="TLP:AMBER+STRICT",
        )
        self.extra_import_last_seen_time_window = get_config_variable(
            "PROOFPOINT_ET_INTELLIGENCE_IMPORT_LAST_SEEN_TIME_WINDOW",
            ["proofpoint_et_intelligence", "import_last_seen_time_window"],
            self.load,
            default="P30D",
        )

        # Validation of environment variables
        try:
            global_variables_json = ProofpointEtIntelligenceConfigVar.model_validate(
                dict(
                    # OpenCTI configurations
                    opencti_url=self.opencti_url,  # Required
                    opencti_token=self.opencti_token,  # Required
                    # Connector configurations
                    connector_id=self.connector_id,  # Required
                    connector_type=self.connector_type,  # Optional
                    connector_name=self.connector_name,  # Optional
                    connector_scope=self.connector_scope,  # Optional
                    connector_log_level=self.connector_log_level,  # Optional
                    connector_auto=self.connector_auto,  # Optional
                    # ProofPoint ET Intelligence Extra parameters
                    extra_api_key=self.extra_api_key,  # Required
                    extra_api_base_url=self.extra_api_base_url,  # Optional
                    extra_max_tlp=self.extra_max_tlp,  # Optional
                    extra_import_last_seen_time_window=self.extra_import_last_seen_time_window,  # Optional
                )
            ).model_dump()

            # Re-assigning environment variables after Models
            for name_variable in global_variables_json:
                setattr(self, name_variable, global_variables_json[name_variable])

            prefixes = {
                "opencti_": "opencti",
                "connector_": "connector",
                "extra_": "proofpoint_et_intelligence",
            }

            # Re-assigning environment variables in self.load
            for key, value in global_variables_json.items():
                for prefix, section in prefixes.items():
                    if key.startswith(prefix):
                        new_key = key[len(prefix) :]
                        self.load.setdefault(section, {}).update({new_key: value})
                        break

        except ValidationError as err:
            raise ValueError(err)
