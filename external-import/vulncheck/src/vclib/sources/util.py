import re
from io import StringIO
from typing import Any, List, Optional

from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel


def parse_cpe_uri(cpe_str: str) -> dict[str, str]:
    """Parse CPE URI following format 1 or 2.3.

    Args:
        cpe_str: the CPE URI

    Returns:
        (dict[str|str]):  {"part": part, "vendor": vendor, "product": product, "version": version}

    Examples:
        >>> dct = parse_cpe_uri("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
    """
    supported_patterns = {
        "cpe:/": r"^cpe:/(?P<part>[a-z]):(?P<vendor>[a-zA-Z0-9_\-]+):(?P<product>[a-zA-Z0-9_\-]+):(?P<version>[a-zA-Z0-9_\-]+)",
        "cpe:2.3": r"^cpe:2\.3:(?P<part>[a-z]+):(?P<vendor>[^:]+):(?P<product>[^:]+):(?P<version>[^:]+)",
    }
    for key, supported_pattern in supported_patterns.items():
        if cpe_str.startswith(key):
            match = re.match(pattern=supported_pattern, string=cpe_str)
            if match is not None:
                return {
                    "part": match.group("part"),
                    "vendor": match.group("vendor"),
                    "product": match.group("product"),
                    "version": match.group("version"),
                }
            raise ValueError("CPE URI is missing mandatory information.")
    raise NotImplementedError("Unknown CPE URI format")


class Rule(BaseModel):
    name: str
    description: str
    rule: str


class RuleParser:
    _RULE_STARTS: tuple[str] = ("alert",)
    _RULE_ENDS = (";)\n",)

    _NAME_PATTERN = r'msg:".*?(VULNCHECK[^"]+?)";'
    _NAME_REGEX = re.compile(_NAME_PATTERN)

    _DESCRIPTION_PATTERN = r'msg:".*(VULNCHECK[^"]+?)";'
    _DESCRIPTION_REGEX = re.compile(_DESCRIPTION_PATTERN)

    _SID_PATTERN = r"sid:(\d+);"
    _SID_REGEX = re.compile(_SID_PATTERN)

    @classmethod
    def parse(cls, rules: str, helper: OpenCTIConnectorHelper) -> List[Rule]:
        """Parse Snort/Suricata rules string to list of Rule model."""
        if not rules:
            helper.connector_logger.warning("No rules to parse, empty string")
            return []

        rules_list = cls._split_rules(rules)
        if not rules_list:
            helper.connector_logger.warning(f"No rules in the given string: {rules}")
            return []

        helper.connector_logger.info(
            f"Found {len(rules_list)} rules in the given string"
        )

        return cls._parse_snort_rules_list(rules_list, helper)

    @classmethod
    def _split_rules(cls, snort_rules_str: str) -> List[str]:
        rule_buffer = None

        result: List[str] = []
        for line in StringIO(snort_rules_str).readlines():
            if rule_buffer is None and line.startswith(cls._RULE_STARTS):
                rule_buffer = StringIO()

            if rule_buffer is not None:
                rule_buffer.write(line)

            if rule_buffer is not None and line.endswith(cls._RULE_ENDS):
                rule = rule_buffer.getvalue()
                result.append(rule)

                rule_buffer.close()
                rule_buffer = None

        return result

    @classmethod
    def _parse_snort_rules_list(
        cls, snort_rule_list: List[str], helper: OpenCTIConnectorHelper
    ) -> List[Rule]:
        result: List[Rule] = []
        for snort_rule in snort_rule_list:
            rule = cls._parse_snort_rule(snort_rule, helper)
            if rule is None:
                continue

            result.append(rule)
        return result

    @classmethod
    def _parse_snort_rule(
        cls, snort_rule: str, helper: OpenCTIConnectorHelper
    ) -> Optional[Rule]:
        name = cls._get_name(snort_rule)
        if name is None:
            helper.connector_logger.error(f"No name for rule: {snort_rule}")
            return None

        description = cls._get_description(snort_rule)
        if description is None:
            helper.connector_logger.error(f"No description for rule: {snort_rule}")
            return None

        helper.connector_logger.debug(f"Creating rule: {snort_rule}")
        rule = Rule(
            name=name,
            description=description,
            rule=snort_rule,
        )
        return rule

    @classmethod
    def _get_name(cls, snort_rule: str) -> Optional[str]:
        return f"VulnCheck_{cls._match_regex(cls._NAME_REGEX, snort_rule)}_{cls._get_sid(snort_rule)}"

    @classmethod
    def _get_sid(cls, snort_rule: str) -> Optional[str]:
        return cls._match_regex(cls._SID_REGEX, snort_rule)

    @classmethod
    def _get_description(cls, snort_rule: str) -> Optional[str]:
        return cls._match_regex(cls._DESCRIPTION_REGEX, snort_rule)

    @staticmethod
    def _match_regex(regex: re.Pattern[Any], string: str) -> Optional[str]:
        match = regex.search(string)
        if match:
            return match.group(1)
        else:
            return None
