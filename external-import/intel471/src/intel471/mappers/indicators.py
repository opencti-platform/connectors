import datetime

from stix2 import Indicator, Bundle, Relationship, Malware, KillChainPhase

from .common import StixMapper, BaseMapper, generate_id, author_identity
from .patterning import STIXPatterningMapper


@StixMapper.register("indicators", lambda x: "indicatorTotalCount" in x)
class IndicatorsMapper(BaseMapper):

    def map(self, source: dict) -> Bundle:
        container = {}
        items = source.get("indicators") or [] if "indicatorTotalCount" in source else [source]
        for item in items:
            malware_family_name = item["data"]["threat"]["data"]["family"]
            malware_family_uid = item["data"]["threat"]["data"]["malware_family_profile_uid"]
            valid_from = datetime.datetime.fromtimestamp(item["activity"]["first"] / 1000)
            valid_until = datetime.datetime.fromtimestamp(item["data"]["expiration"] / 1000)
            description = item["data"]["context"]["description"]
            tactics = self.map_tactic(item["data"]["mitre_tactics"])
            indicator_id = item["uid"]
            indicator_type = item["data"]["indicator_type"]
            indicator_data = item["data"]["indicator_data"]
            confidence = self.map_confidence(item["data"]["confidence"])

            if pattern_mapper := getattr(STIXPatterningMapper, f"map_{indicator_type}", None):
                stix_pattern = pattern_mapper(indicator_data)

                malware = Malware(id=generate_id(Malware, name=malware_family_name.strip().lower()),
                                  name=malware_family_name,
                                  is_family=True,
                                  created_by_ref=author_identity,
                                  custom_properties={"x_intel471_com_uid": malware_family_uid})
                indicator = Indicator(id=generate_id(Indicator, pattern=stix_pattern),
                                      description=description,
                                      indicator_types=["malicious-activity"],
                                      pattern_type="stix",
                                      pattern=stix_pattern,
                                      valid_from=valid_from,
                                      valid_until=valid_until,
                                      kill_chain_phases=[KillChainPhase(kill_chain_name="mitre-attack", phase_name=tactics)],
                                      created_by_ref=author_identity,
                                      confidence=confidence,
                                      custom_properties={"x_intel471_com_uid": indicator_id})
                r1 = Relationship(indicator, "indicates", malware, created_by_ref=author_identity)
                for stix_object in [malware, indicator, author_identity, r1]:
                    container[stix_object.id] = stix_object
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle
