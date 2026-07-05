"""Aegis detection engine - pure logic (no AWS SDK), fully unit-testable.

Design: detection-as-code. Every rule is a declarative entry in RULES with an
id, human name, severity, a compiled signature (for signature rules), and a
MITRE ATT&CK technique + tactic. The handler layers stateful statistics
(rate / brute force) and threat-intel enrichment on top. Findings are also
mapped to the OCSF Detection Finding class so the schema is portable.
"""
import math
import re


# ATT&CK tactics we map into (ordered as a mini kill-chain)
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0005", "Defense Evasion"),
    ("TA0040", "Impact"),
]


def _rx(p):
    return re.compile(p, re.I)


# Rule catalog. `sig` marks a signature rule; `stat` marks a behavioral rule
# raised by the handler. Everything else is shared metadata.
RULES = [
    dict(id="sqli", name="SQL Injection", severity="HIGH",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="SQL metacharacters or boolean/union patterns in request input.",
         sig=_rx(r"('|%27)?\s*(or|and)\s+\d+\s*=\s*\d+|union\s+select|select\s+.+\s+from"
                 r"|insert\s+into|drop\s+table|;\s*--|/\*|xp_cmdshell|sleep\s*\(|benchmark\s*\(")),
    dict(id="xss", name="Cross-Site Scripting", severity="MEDIUM",
         technique="T1059.007", technique_name="JavaScript", tactic="Execution",
         desc="HTML/JS injection patterns in request input.",
         sig=_rx(r"<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|%3cscript|document\.cookie|alert\s*\(")),
    dict(id="command_injection", name="OS Command Injection", severity="CRITICAL",
         technique="T1059", technique_name="Command and Scripting Interpreter",
         tactic="Execution",
         desc="Shell metacharacters chaining OS commands.",
         sig=_rx(r";\s*(cat|ls|wget|curl|nc|bash|sh|id|whoami)\b|`[^`]+`|\$\([^)]+\)|\|\s*(cat|ls|id|whoami)\b|&&\s*(cat|ls|id)\b")),
    dict(id="log4shell", name="Log4Shell / JNDI Injection", severity="CRITICAL",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="JNDI lookup string (CVE-2021-44228 family).",
         sig=_rx(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop)://")),
    dict(id="ssti", name="Server-Side Template Injection", severity="HIGH",
         technique="T1059", technique_name="Command and Scripting Interpreter",
         tactic="Execution",
         desc="Template expression syntax such as {{7*7}} or ${...}.",
         sig=_rx(r"\{\{.*[\*\+].*\}\}|\$\{[^}]+\}|#\{[^}]+\}|<%=.+%>")),
    dict(id="nosqli", name="NoSQL Injection", severity="HIGH",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="MongoDB-style operators in input.",
         sig=_rx(r"\$ne\b|\$gt\b|\$lt\b|\$where\b|\$regex\b|\{\s*\"?\$")),
    dict(id="xxe", name="XML External Entity", severity="HIGH",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="External entity / DOCTYPE SYSTEM declaration.",
         sig=_rx(r"<!entity|<!doctype[^>]+system|SYSTEM\s+\"file:")),
    dict(id="path_traversal", name="Path Traversal", severity="HIGH",
         technique="T1083", technique_name="File and Directory Discovery",
         tactic="Discovery",
         desc="Directory traversal sequences.",
         sig=_rx(r"\.\./|\.\.%2f|%2e%2e%2f|\.\.\\|/etc/passwd|/proc/self|c:\\windows")),
    dict(id="lfi_rfi", name="File Inclusion (LFI/RFI)", severity="HIGH",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="PHP wrappers or remote include of a script.",
         sig=_rx(r"php://(filter|input)|file://|data://|expect://|=https?://[^ ]+\.(php|txt)\b")),
    dict(id="ssrf", name="Server-Side Request Forgery", severity="HIGH",
         technique="T1552.005", technique_name="Cloud Instance Metadata API",
         tactic="Credential Access",
         desc="Requests coerced toward internal or cloud-metadata addresses.",
         sig=_rx(r"169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|=https?://(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.")),
    dict(id="open_redirect", name="Open Redirect", severity="LOW",
         technique="T1189", technique_name="Drive-by Compromise", tactic="Initial Access",
         desc="Redirect/next parameter pointing off-site.",
         sig=_rx(r"(redirect|next|url|return|dest)=(https?:)?//")),
    dict(id="sensitive_file", name="Sensitive File Access", severity="MEDIUM",
         technique="T1083", technique_name="File and Directory Discovery",
         tactic="Discovery",
         desc="Probing for secrets, VCS, backups, or config files.",
         sig=_rx(r"/\.(env|git|svn|htpasswd|aws)|/(backup|dump|db)\.(sql|zip|tar|gz)|/(wp-config|config)\.(php|json|ya?ml)|/id_rsa|/phpinfo")),
    dict(id="scanner", name="Automated Scanner", severity="LOW",
         technique="T1595", technique_name="Active Scanning", tactic="Reconnaissance",
         desc="Known offensive-tool user agents.",
         sig=_rx(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|zgrab|feroxbuster|(python-requests|curl|go-http-client)/")),
    dict(id="pii_exposure", name="Sensitive Data in Request", severity="MEDIUM",
         technique="T1552", technique_name="Unsecured Credentials", tactic="Credential Access",
         desc="PII/secret patterns (email, card, key) present in input.",
         sig=_rx(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\b(?:\d[ -]*?){13,16}\b|AKIA[0-9A-Z]{16}|-----BEGIN")),
    # app-emitted signals (no signature; forwarded by the honeypot)
    dict(id="unauthorized_admin_access", name="Admin Access Attempt", severity="HIGH",
         technique="T1078", technique_name="Valid Accounts", tactic="Defense Evasion",
         desc="Direct request to an administrative surface."),
    dict(id="idor_probe", name="Broken Access Control (IDOR)", severity="MEDIUM",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access",
         desc="Object reference manipulated to reach another user's resource."),
    dict(id="recon_404", name="Recon / Enumeration", severity="LOW",
         technique="T1595", technique_name="Active Scanning", tactic="Reconnaissance",
         desc="Probing for non-existent paths (content discovery)."),
    dict(id="http_method_abuse", name="Dangerous HTTP Method", severity="LOW",
         technique="T1190", technique_name="Exploit Public-Facing Application",
         tactic="Initial Access", desc="Use of PUT/DELETE/TRACE against the app."),
    # statistical / behavioral (raised by the handler)
    dict(id="brute_force", name="Brute Force", severity="HIGH",
         technique="T1110", technique_name="Brute Force", tactic="Credential Access",
         desc="Many failed logins from one source in a short window.", stat=True),
    dict(id="credential_stuffing", name="Credential Stuffing", severity="HIGH",
         technique="T1110.004", technique_name="Credential Stuffing",
         tactic="Credential Access",
         desc="Failed logins across many distinct usernames from one source.", stat=True),
    dict(id="rate_anomaly", name="Request-Rate Anomaly", severity="MEDIUM",
         technique="T1498", technique_name="Network Denial of Service", tactic="Impact",
         desc="Request rate from one source far above baseline.", stat=True),
    dict(id="blocked_request", name="Blocked Source Retry", severity="LOW",
         technique="T1498", technique_name="Network Denial of Service", tactic="Impact",
         desc="A blocked source is still sending requests.", stat=True),
    dict(id="new_source", name="New Source", severity="INFO",
         technique=None, technique_name=None, tactic=None,
         desc="First time this source has been observed.", stat=True),
]

RULES_BY_ID = {r["id"]: r for r in RULES}
SIGNATURE_RULES = [r for r in RULES if "sig" in r]
APP_SIGNALS = {"unauthorized_admin_access", "idor_probe", "recon_404",
               "http_method_abuse", "login_failed"}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _blob(event):
    parts = [event.get(f, "") for f in ("path", "query", "user_agent", "body", "referer")]
    return " ".join(str(p) for p in parts)


def signature_scan(event):
    """Return the list of matched signature rule ids for one event."""
    blob = _blob(event)
    hits = [r["id"] for r in SIGNATURE_RULES if r["sig"].search(blob)]
    app_sig = event.get("signal")
    if app_sig in APP_SIGNALS and app_sig != "login_failed" and app_sig not in hits:
        hits.append(app_sig)
    return hits


def severity_of(signal):
    r = RULES_BY_ID.get(signal)
    return r["severity"] if r else "LOW"


def max_severity(signals):
    best = "INFO"
    for s in signals:
        sv = severity_of(s)
        if SEVERITY_ORDER[sv] > SEVERITY_ORDER[best]:
            best = sv
    return best


def escalate(base, steps=1):
    lvl = min(SEVERITY_ORDER[base] + steps, SEVERITY_ORDER["CRITICAL"])
    return next(name for name, n in SEVERITY_ORDER.items() if n == lvl)


def score(signals, stat_signals):
    """Final severity: max of all signals, escalated one step when a signature
    and a behavioral signal (other than new_source) corroborate from one source."""
    base = max_severity(list(signals) + list(stat_signals))
    if signals and [s for s in stat_signals if s != "new_source"]:
        base = escalate(base, 1)
    return base


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_LEN = 24


def entropy_anomaly(event):
    q = str(event.get("query", ""))
    return len(q) >= ENTROPY_MIN_LEN and shannon_entropy(q) >= ENTROPY_THRESHOLD


def mitre_for(signals):
    """Deduplicated list of ATT&CK techniques for the given signals."""
    seen, out = set(), []
    for s in signals:
        r = RULES_BY_ID.get(s)
        if r and r.get("technique") and r["technique"] not in seen:
            seen.add(r["technique"])
            out.append({"technique": r["technique"], "name": r["technique_name"],
                        "tactic": r["tactic"]})
    return out


_OCSF_SEV = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def ocsf_finding(event, signals, severity, finding_id):
    """Map to OCSF Detection Finding (class_uid 2004)."""
    primary = signals[0] if signals else "unknown"
    rule = RULES_BY_ID.get(primary, {})
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": _OCSF_SEV.get(severity, 1),
        "severity": severity.capitalize(),
        "time": event.get("ts_epoch"),
        "metadata": {"product": {"name": "Aegis", "vendor_name": "Aegis SIEM"},
                     "version": "1.1.0"},
        "finding_info": {"uid": finding_id, "title": rule.get("name", primary),
                         "desc": rule.get("desc", "")},
        "attacks": [{"technique": {"uid": m["technique"], "name": m["name"]},
                     "tactic": {"name": m["tactic"]}} for m in mitre_for(signals)],
        "src_endpoint": {"ip": event.get("src_ip")},
        "observables": [{"name": "src_ip", "type": "IP Address",
                         "value": event.get("src_ip")}],
    }
