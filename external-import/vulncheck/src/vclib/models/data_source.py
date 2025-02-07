from enum import Enum

from vclib.sources.botnets import collect_botnets
from vclib.sources.epss import collect_epss
from vclib.sources.exploits import collect_exploits
from vclib.sources.initial_access import collect_initial_access
from vclib.sources.ipintel import collect_ipintel
from vclib.sources.nistnvd2 import collect_nistnvd2
from vclib.sources.ransomware import collect_ransomware
from vclib.sources.snort import collect_snort
from vclib.sources.suricata import collect_suricata
from vclib.sources.threat_actors import collect_threat_actors
from vclib.sources.vckev import collect_vckev
from vclib.sources.vcnvd2 import collect_vcnvd2

BOTNETS = "botnets"
EPSS = "epss"
EXPLOITS = "exploits"
INITIAL_ACCESS = "initial-access"
IPINTEL = "ipintel"
NIST_NVD2 = "nist-nvd2"
RANSOMWARE = "ransomware"
SNORT = "snort"
SURICATA = "suricata"
THREAT_ACTORS = "threat-actors"
VULNCHECK_KEV = "vulncheck-kev"
VULNCHECK_NVD2 = "vulncheck-nvd2"


class DataSource(Enum):
    Botnets = (BOTNETS, collect_botnets)
    Epss = (EPSS, collect_epss)
    Exploits = (EXPLOITS, collect_exploits)
    IPIntel = (IPINTEL, collect_ipintel)
    InitialAccess = (INITIAL_ACCESS, collect_initial_access)
    NistNVD2 = (NIST_NVD2, collect_nistnvd2)
    Ransomware = (RANSOMWARE, collect_ransomware)
    Snort = (SNORT, collect_snort)
    Suricata = (SURICATA, collect_suricata)
    ThreatActors = (THREAT_ACTORS, collect_threat_actors)
    VulnCheckKEV = (VULNCHECK_KEV, collect_vckev)
    VulnCheckNVD2 = (VULNCHECK_NVD2, collect_vcnvd2)

    def __init__(self, name, collect_data_source):
        self._name = name
        self.collect_data_source = collect_data_source

    @property
    def name(self):
        return self._name

    @classmethod
    def from_string(cls, name):
        for item in cls:
            if item.name == name:
                return item
        raise ValueError(f"Unknown Data Source name: {name}")

    @classmethod
    def get_all_data_source_strings(cls):
        return ",".join([item.name for item in cls])
