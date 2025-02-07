import re


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
