import json
from datetime import date, datetime

WEIGHTS = {
    "source_reputation": 0.30,
    "times_seen": 0.25,
    "recency": 0.20,
    "asset_relevance": 0.15,
    "malware_severity": 0.10,
}

SOURCE_REPUTATION = {
    "Internal Honeypot": 90,
    "VirusTotal": 80,
    "PhishTank": 65,
    "AlienVault OTX": 50,
    "AbuseIPDB": 35,
}

MALWARE_SEVERITY = {
    "LockBit": 100,
    "Cobalt Strike": 95,
    "Emotet": 90,
    "QakBot": 85,
    "AgentTesla": 75,
    "Mirai": 70,
    "None": 10,
}

FAMILY_TAGS = {
    "LockBit": ["ransomware"],
    "Cobalt Strike": ["C2"],
    "Emotet": ["botnet"],
    "Mirai": ["botnet"],
    "QakBot": ["banking-trojan"],
    "AgentTesla": ["infostealer"],
}

PHISH_WORDS = ["login", "verify", "bank", "account", "secure", "pay", "update", "support"]


def recency_value(first_seen):
    try:
        days = (date.today() - datetime.strptime(first_seen, "%Y-%m-%d").date()).days
    except (ValueError, TypeError):
        return 10
    if days <= 7:
        return 100
    if days <= 30:
        return 60
    if days <= 60:
        return 30
    return 10


def asset_relevance_value(ind):
    if ind.type == "domain":
        return 85 if any(w in ind.value for w in PHISH_WORDS) else 40
    if ind.type == "hash":
        return 55
    return 40


def build_tags(ind):
    tags = list(FAMILY_TAGS.get(ind.malware_family, []))
    if ind.type == "domain" and any(w in ind.value for w in PHISH_WORDS):
        tags.append("phishing")
    if ind.type == "ip" and ind.malware_family == "None":
        tags.append("scanner")
    if ind.source == "Internal Honeypot":
        tags.append("honeypot-hit")
    return list(dict.fromkeys(tags))


def severity_of(score):
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def score_indicator(ind):
    values = {
        "source_reputation": SOURCE_REPUTATION.get(ind.source, 50),
        "times_seen": min(100, ind.times_seen or 0),
        "recency": recency_value(ind.first_seen),
        "asset_relevance": asset_relevance_value(ind),
        "malware_severity": MALWARE_SEVERITY.get(ind.malware_family, 20),
    }
    breakdown = []
    total = 0.0
    for factor, value in values.items():
        points = round(value * WEIGHTS[factor], 1)
        total += points
        breakdown.append(
            {"factor": factor, "value": value, "weight": WEIGHTS[factor], "points": points}
        )
    score = round(total)
    return {
        "score": score,
        "severity": severity_of(score),
        "tags": ",".join(build_tags(ind)),
        "breakdown": json.dumps(breakdown),
    }
