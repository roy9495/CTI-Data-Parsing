from stix2 import Indicator, Bundle
from datetime import datetime
import uuid

def create_stix_bundle(records, source_platform):
    indicators = []

    for row in records:
        ioc = row.get("ioc")
        confidence = int(row.get("confidence", 70))

        if not ioc:
            continue

        # Auto-detect indicator type based on IOC format
        if ":" in ioc or "." in ioc and "/" not in ioc:
            indicator_type = "ipv4-addr"
            pattern = f"[ipv4-addr:value = '{ioc}']"
        elif "/" in ioc:
            indicator_type = "url"
            pattern = f"[url:value = '{ioc}']"
        else:
            indicator_type = "domain-name"
            pattern = f"[domain-name:value = '{ioc}']"

        indicators.append(Indicator(
            id=f"indicator--{uuid.uuid4()}",
            pattern=pattern,
            pattern_type="stix",
            labels=["malicious-activity"],
            confidence=confidence,
            custom_properties={  # custom fields must be allowed in the bundle
                "x_source_platform": source_platform,
                "x_ioc_value": ioc,
                "x_ioc_type": indicator_type
            }
        ))

    # ✅ THIS is the fix
    return Bundle(objects=indicators, allow_custom=True)
