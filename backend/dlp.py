import re


def luhn_ok(number):
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(number):
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][d]]
    return c == 0


def mask_aadhaar(v):
    d = re.sub(r"\D", "", v)
    return "XXXX XXXX " + d[-4:]


def mask_card(v):
    d = re.sub(r"\D", "", v)
    return "**** **** **** " + d[-4:]


def mask_email(v):
    user, domain = v.split("@", 1)
    return user[0] + "***@" + domain


def mask_phone(v):
    d = re.sub(r"\D", "", v)
    return "******" + d[-4:]


def mask_generic(v):
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * 6 + v[-4:]


def mask_pan(v):
    return v[:2] + "*" * 7 + v[-1]


RULES = [
    ("Aadhaar number", "High", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), verhoeff_ok, mask_aadhaar),
    ("Credit/debit card", "High", re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)"), luhn_ok, mask_card),
    ("PAN card", "High", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), None, mask_pan),
    ("AWS access key", "High", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None, mask_generic),
    ("Stripe secret key", "High", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"), None, mask_generic),
    ("GitHub token", "High", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None, mask_generic),
    ("Google API key", "High", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None, mask_generic),
    ("Hardcoded secret", "High", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-@#$%!]{8,}['\"]?"), None, mask_generic),
    ("Email address", "Medium", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), None, mask_email),
    ("Phone number (India)", "Medium", re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"), None, mask_phone),
]


def scan_text(text):
    findings = []
    taken = []

    for label, severity, regex, validator, masker in RULES:
        for m in regex.finditer(text):
            s, e = m.start(), m.end()
            if any(s < te and e > ts for ts, te in taken):
                continue
            raw = m.group(0)
            if validator and not validator(raw):
                continue
            taken.append((s, e))
            findings.append({
                "type": label,
                "severity": severity,
                "masked": masker(raw),
                "start": s,
                "end": e,
            })

    findings.sort(key=lambda f: f["start"])

    redacted, last = [], 0
    for f in findings:
        redacted.append(text[last:f["start"]])
        redacted.append("[" + f["type"].upper() + ": " + f["masked"] + "]")
        last = f["end"]
    redacted.append(text[last:])

    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1

    if any(f["severity"] == "High" for f in findings):
        risk = "High"
    elif findings:
        risk = "Medium"
    else:
        risk = "Clean"

    return {
        "risk": risk,
        "total_findings": len(findings),
        "counts": counts,
        "findings": findings,
        "redacted_text": "".join(redacted),
    }
