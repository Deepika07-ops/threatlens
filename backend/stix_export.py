import uuid
from datetime import datetime, timezone

import stix2
from stix2.v21 import TLP_AMBER

NS = uuid.UUID("6f1c2a52-8b0e-4c1e-9d55-0b7a5e2c3a11")


def _sid(kind, key):
    return "%s--%s" % (kind, uuid.uuid5(NS, key))


def _esc(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(ind):
    if ind.type == "ip":
        return "[ipv4-addr:value = '%s']" % _esc(ind.value)
    if ind.type == "domain":
        return "[domain-name:value = '%s']" % _esc(ind.value)
    if ind.type == "hash":
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(ind.value), "MD5")
        return "[file:hashes.'%s' = '%s']" % (algo, _esc(ind.value))
    return None


def _valid_from(first_seen):
    try:
        return datetime.strptime(first_seen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def build_bundle(items):
    identity = stix2.Identity(
        id=_sid("identity", "threatlens"),
        name="ThreatLens",
        identity_class="system",
        description="Threat intelligence triage platform (academic project).",
        object_marking_refs=[TLP_AMBER],
    )
    objects = [TLP_AMBER, identity]
    malware = {}

    for ind in items:
        pattern = _pattern(ind)
        if not pattern:
            continue
        labels = [t for t in (ind.tags or "").split(",") if t]
        desc = "%s indicator from %s. Risk score %s/100 (%s). Seen %s times." % (
            ind.type.upper(), ind.source, ind.score, ind.severity, ind.times_seen)
        if ind.analyst_note:
            desc += " Analyst note: " + ind.analyst_note
        kwargs = dict(
            id=_sid("indicator", "%s:%s" % (ind.type, ind.value)),
            name="%s %s" % (ind.type, ind.value),
            description=desc,
            pattern=pattern,
            pattern_type="stix",
            valid_from=_valid_from(ind.first_seen),
            indicator_types=["malicious-activity"],
            confidence=int(ind.score or 0),
            created_by_ref=identity.id,
            object_marking_refs=[TLP_AMBER],
        )
        if labels:
            kwargs["labels"] = labels
        indicator = stix2.Indicator(**kwargs)
        objects.append(indicator)

        fam = ind.malware_family
        if fam and fam != "None":
            if fam not in malware:
                malware[fam] = stix2.Malware(
                    id=_sid("malware", fam),
                    name=fam,
                    is_family=True,
                    malware_types=["unknown"],
                    created_by_ref=identity.id,
                    object_marking_refs=[TLP_AMBER],
                )
                objects.append(malware[fam])
            objects.append(stix2.Relationship(
                id=_sid("relationship", "%s>%s" % (indicator.id, malware[fam].id)),
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware[fam].id,
                created_by_ref=identity.id,
                object_marking_refs=[TLP_AMBER],
            ))

    return stix2.Bundle(objects=objects, allow_custom=False)
