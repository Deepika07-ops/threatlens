import csv
import random
from datetime import datetime, timedelta

random.seed(42)

SOURCES = ["AlienVault OTX", "AbuseIPDB", "PhishTank", "VirusTotal", "Internal Honeypot"]
FAMILIES = ["Emotet", "Mirai", "LockBit", "AgentTesla", "Cobalt Strike", "QakBot", "None"]
WORDS = ["secure", "login", "update", "verify", "bank", "account", "support", "pay"]
TLDS = [".xyz", ".top", ".info", ".click", ".ru"]


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def rand_domain():
    return f"{random.choice(WORDS)}-{random.choice(WORDS)}{random.choice(TLDS)}"


def rand_hash():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def make_row(ioc_type, value):
    first_seen = datetime.now() - timedelta(days=random.randint(0, 60))
    return {
        "type": ioc_type,
        "value": value,
        "source": random.choice(SOURCES),
        "first_seen": first_seen.strftime("%Y-%m-%d"),
        "count": random.randint(1, 120),
        "malware_family": random.choice(FAMILIES),
    }


rows = []
rows += [make_row("ip", rand_ip()) for _ in range(20)]
rows += [make_row("domain", rand_domain()) for _ in range(18)]
rows += [make_row("hash", rand_hash()) for _ in range(12)]

# 3 deliberate duplicates to test duplicate removal later
for r in rows[:3]:
    dup = dict(r)
    dup["count"] = random.randint(1, 50)
    rows.append(dup)

random.shuffle(rows)

with open("data/sample_feed.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f, fieldnames=["type", "value", "source", "first_seen", "count", "malware_family"]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Created data/sample_feed.csv with {len(rows)} rows")
