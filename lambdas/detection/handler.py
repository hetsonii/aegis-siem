"""Detection Lambda.

Triggers:
  * SQS - one normalized event per record -> rules + statistics + enrichment
  * EventBridge (scheduled) - correlation sweep over recent detection state

Adds to each finding: GeoIP (cached), MITRE ATT&CK techniques, an OCSF
Detection Finding mapping, and an epoch timestamp for time-range queries.
"""
import json
import os
import time
import uuid
import urllib.request
from decimal import Decimal
import boto3
from boto3.dynamodb.conditions import Key

import detector

ddb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
sns = boto3.client("sns")

FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
STATE_TABLE = os.environ["STATE_TABLE"]
LAKE_BUCKET = os.environ["LAKE_BUCKET"]
TOPIC_ARN = os.environ["TOPIC_ARN"]
THRESHOLD = os.environ.get("ALERT_THRESHOLD", "HIGH")

findings = ddb.Table(FINDINGS_TABLE)
state = ddb.Table(STATE_TABLE)

WINDOW_SECONDS = 60
RATE_THRESHOLD = 30
BRUTE_FORCE_THRESHOLD = 8
CRED_STUFFING_DISTINCT = 5
STATE_TTL_SECONDS = 3600
SEEN_TTL_SECONDS = 86400
GEO_TTL_SECONDS = 86400


def _bucket(now=None):
    return int(now or time.time()) // WINDOW_SECONDS


def _incr(state_key, ttl_seconds):
    resp = state.update_item(
        Key={"state_key": state_key},
        UpdateExpression="ADD #c :one SET #t = :ttl",
        ExpressionAttributeNames={"#c": "count", "#t": "ttl"},
        ExpressionAttributeValues={":one": 1, ":ttl": int(time.time()) + ttl_seconds},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["count"])


def _add_to_set(state_key, value, ttl_seconds):
    resp = state.update_item(
        Key={"state_key": state_key},
        UpdateExpression="ADD members :v SET #t = :ttl",
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues={":v": {value}, ":ttl": int(time.time()) + ttl_seconds},
        ReturnValues="UPDATED_NEW",
    )
    return len(resp["Attributes"].get("members", []))


def _first_seen(ip):
    try:
        state.put_item(
            Item={"state_key": f"SEEN#{ip}", "ttl": int(time.time()) + SEEN_TTL_SECONDS},
            ConditionExpression="attribute_not_exists(state_key)",
        )
        return True
    except ddb.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def geo_lookup(ip):
    """Cached GeoIP enrichment via a free, keyless service."""
    key = f"GEO#{ip}"
    try:
        cached = state.get_item(Key={"state_key": key}).get("Item")
        if cached and "geo" in cached:
            return json.loads(cached["geo"])
    except Exception:  # noqa
        pass

    geo = {"country": "Unknown", "country_code": "", "city": "", "lat": 0, "lon": 0}
    try:
        url = ("http://ip-api.com/json/%s?fields=status,country,countryCode,city,lat,lon" % ip)
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            geo = {"country": data.get("country", "Unknown"),
                   "country_code": data.get("countryCode", ""),
                   "city": data.get("city", ""),
                   "lat": data.get("lat", 0), "lon": data.get("lon", 0)}
    except Exception:  # noqa - enrichment is best-effort
        pass

    try:
        state.put_item(Item={"state_key": key, "geo": json.dumps(geo),
                             "ttl": int(time.time()) + GEO_TTL_SECONDS})
    except Exception:  # noqa
        pass
    return geo


def statistical_layer(event):
    """Return (stat_signals, context) using shared per-source counters."""
    ip = event.get("src_ip", "unknown")
    win = _bucket()
    signals, ctx = [], {}

    if event.get("signal") == "blocked_request":
        signals.append("blocked_request")

    rate = _incr(f"RATE#{ip}#{win}", STATE_TTL_SECONDS)
    ctx["rate"] = rate
    if rate > RATE_THRESHOLD:
        signals.append("rate_anomaly")

    is_login_fail = (event.get("signal") == "login_failed"
                     or "login_failed" in (event.get("detail") or {}).get("signals", []))
    if is_login_fail:
        fails = _incr(f"FAIL#{ip}#{win}", STATE_TTL_SECONDS)
        ctx["failed_logins"] = fails
        if fails >= BRUTE_FORCE_THRESHOLD:
            signals.append("brute_force")
        username = (event.get("detail") or {}).get("username")
        if username:
            distinct = _add_to_set(f"CREDS#{ip}#{win}", str(username)[:64], STATE_TTL_SECONDS)
            ctx["distinct_usernames"] = distinct
            if distinct >= CRED_STUFFING_DISTINCT:
                signals.append("credential_stuffing")

    if detector.entropy_anomaly(event):
        signals.append("rate_anomaly")
        ctx["high_entropy"] = True

    if _first_seen(ip):
        signals.append("new_source")

    return signals, ctx


def _ddb_safe(obj):
    """Return a copy of obj with all floats converted to Decimal (and any
    non-JSON types stringified), so boto3 can serialize it for DynamoDB."""
    return json.loads(json.dumps(obj, default=str), parse_float=Decimal)


def write_finding(event, signals, stat_signals, severity, ctx, geo):
    fid = str(uuid.uuid4())
    now = int(time.time())
    all_sig = signals + stat_signals
    evidence_key = f"evidence/dt={time.strftime('%Y/%m/%d')}/{fid}.json"
    ocsf = detector.ocsf_finding(event, all_sig, severity, fid)
    s3.put_object(
        Bucket=LAKE_BUCKET, Key=evidence_key,
        Body=json.dumps({"event": event, "signals": signals, "stat_signals": stat_signals,
                         "context": ctx, "geo": geo, "ocsf": ocsf}, default=str),
        ContentType="application/json")
    item = {
        "finding_id": fid,
        "gsi_pk": "ALL",
        "created_at": event.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ts_epoch": event.get("ts_epoch") or now,
        "severity": severity,
        "type": (all_sig + ["unknown"])[0],
        "signals": all_sig,
        "src_ip": event.get("src_ip", "unknown"),
        "path": event.get("path", ""),
        "method": event.get("method", ""),
        "source": event.get("source", "unknown"),
        "status": "new",
        "alerted": False,
        "evidence_key": evidence_key,
        "context": ctx,
        "geo": geo,
        "country": geo.get("country", "Unknown"),
        "country_code": geo.get("country_code", ""),
        "mitre": detector.mitre_for(all_sig),
        "ocsf_class_uid": 2004,
    }
    # DynamoDB's boto3 resource rejects Python floats (e.g. GeoIP lat/lon), so
    # convert the whole item to Decimal-safe types before writing. We keep the
    # original `item` (with plain floats) for the return value / SNS message.
    findings.put_item(Item=_ddb_safe(item))
    return item


def maybe_alert(item, severity):
    if detector.SEVERITY_ORDER[severity] < detector.SEVERITY_ORDER[THRESHOLD]:
        return
    techniques = ", ".join(m["technique"] for m in item.get("mitre", [])) or "n/a"
    body = (
        f"Aegis SIEM - {severity} finding\n\n"
        f"Type:       {item['type']}\n"
        f"Source IP:  {item['src_ip']}  ({item.get('country', 'Unknown')})\n"
        f"Target:     {item['method']} {item['path']}\n"
        f"Signals:    {', '.join(item['signals'])}\n"
        f"ATT&CK:     {techniques}\n"
        f"Finding ID: {item['finding_id']}\n"
        f"Time:       {item['created_at']}\n"
    )
    sns.publish(TopicArn=TOPIC_ARN,
                Subject=f"[Aegis] {severity} {item['type']} from {item['src_ip']}"[:99],
                Message=json.dumps({"human": body, "finding": item}, default=str))


def process_event(event):
    signals = detector.signature_scan(event)
    stat_signals, ctx = statistical_layer(event)
    if not signals and not stat_signals:
        return None
    if not signals and stat_signals == ["new_source"]:
        return None
    severity = detector.score(signals, stat_signals)
    geo = geo_lookup(event.get("src_ip", "unknown"))
    item = write_finding(event, signals, stat_signals, severity, ctx, geo)
    maybe_alert(item, severity)
    return item


def scheduled_scan():
    created = 0
    win = _bucket()
    resp = state.scan(
        FilterExpression=Key("state_key").begins_with("FAIL#"),
        ProjectionExpression="state_key, #c",
        ExpressionAttributeNames={"#c": "count"})
    for it in resp.get("Items", []):
        if int(it.get("count", 0)) >= BRUTE_FORCE_THRESHOLD and f"#{win}" in it["state_key"]:
            ip = it["state_key"].split("#")[1]
            synthetic = {"src_ip": ip, "source": "correlation", "path": "/api/login",
                         "signal": "login_failed", "ts_epoch": int(time.time()),
                         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
            geo = geo_lookup(ip)
            item = write_finding(synthetic, [], ["brute_force"], "HIGH",
                                 {"failed_logins": int(it["count"]), "via": "scheduled_scan"}, geo)
            maybe_alert(item, "HIGH")
            created += 1
    return created


def handler(event, context):
    if event.get("source") == "aws.events" or event.get("scan") == "scheduled":
        return {"scheduled_findings": scheduled_scan()}

    created = 0
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (KeyError, json.JSONDecodeError):
            continue
        if process_event(body):
            created += 1
    return {"findings": created}