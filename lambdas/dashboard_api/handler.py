"""Dashboard API Lambda (API Gateway HTTP API, $default catch-all route).

Routes (method + path):
  GET    /stats                 overview aggregates (severity/type/status/geo/timeline/MTTA/MTTR)
  GET    /findings              search findings (since, q, severity, type, status, src_ip, country, limit)
  GET    /findings/{id}         finding detail (+ ?evidence=1)
  PATCH  /findings/{id}         update triage status
  GET    /incidents            findings grouped into per-source incidents
  PATCH  /incidents/{ip}        set status on every finding from that source
  GET    /geo                   geo points for the attack map
  GET    /blocklist             list blocked sources
  POST   /blocklist             block a source {src_ip, note}
  DELETE /blocklist/{ip}        unblock a source
"""
import json
import os
import time
from decimal import Decimal
import boto3
from boto3.dynamodb.conditions import Key

ddb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
findings = ddb.Table(os.environ["FINDINGS_TABLE"])
blocklist = ddb.Table(os.environ["BLOCKLIST_TABLE"])
LAKE_BUCKET = os.environ["LAKE_BUCKET"]

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Content-Type": "application/json",
}
STATUSES = ("new", "investigating", "resolved", "false_positive")


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


def resp(status, body):
    return {"statusCode": status, "headers": CORS,
            "body": json.dumps(body, cls=DecimalEncoder)}


def recent(limit=1000):
    out, start = [], None
    while len(out) < limit:
        kw = dict(IndexName="by_time", KeyConditionExpression=Key("gsi_pk").eq("ALL"),
                  ScanIndexForward=False, Limit=min(limit - len(out), 500))
        if start:
            kw["ExclusiveStartKey"] = start
        r = findings.query(**kw)
        out.extend(r.get("Items", []))
        start = r.get("LastEvaluatedKey")
        if not start:
            break
    return out


def _num(v, d=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def _since(qs):
    return _num(qs.get("since"), 0)


def _match(f, qs):
    if f.get("ts_epoch", 0) < _since(qs):
        return False
    for k in ("severity", "status", "type", "src_ip", "country_code"):
        if qs.get(k) and str(f.get(k)) != qs[k]:
            return False
    q = (qs.get("q") or "").strip().lower()
    if q:
        hay = " ".join(str(f.get(x, "")) for x in
                       ("src_ip", "type", "path", "method", "country", "status")).lower()
        hay += " " + " ".join(f.get("signals", []))
        if q not in hay:
            return False
    return True


def list_findings(qs):
    items = [f for f in recent(_num(qs.get("limit"), 500) if qs.get("limit") else 1000)
             if _match(f, qs)]
    limit = _num(qs.get("limit"), 200)
    return resp(200, {"findings": items[:limit], "count": len(items)})


def get_finding(fid, qs):
    item = findings.get_item(Key={"finding_id": fid}).get("Item")
    if not item:
        return resp(404, {"error": "finding not found"})
    if qs.get("evidence") and item.get("evidence_key"):
        try:
            obj = s3.get_object(Bucket=LAKE_BUCKET, Key=item["evidence_key"])
            item["evidence"] = json.loads(obj["Body"].read())
        except Exception as e:  # noqa
            item["evidence_error"] = str(e)
    return resp(200, item)


def _set_status(fid, status):
    now = int(time.time())
    expr = "SET #s = :s"
    names = {"#s": "status"}
    vals = {":s": status}
    if status == "investigating":
        expr += ", acknowledged_at = if_not_exists(acknowledged_at, :a)"
        vals[":a"] = now
    if status in ("resolved", "false_positive"):
        expr += ", resolved_at = :r"
        vals[":r"] = now
    findings.update_item(Key={"finding_id": fid}, UpdateExpression=expr,
                         ExpressionAttributeNames=names, ExpressionAttributeValues=vals)


def patch_finding(fid, body):
    status = (body or {}).get("status")
    if status not in STATUSES:
        return resp(400, {"error": "status must be one of %s" % ", ".join(STATUSES)})
    _set_status(fid, status)
    return resp(200, {"finding_id": fid, "status": status})


def incidents(qs):
    groups = {}
    for f in recent(1000):
        if not _match(f, qs):
            continue
        ip = f.get("src_ip", "unknown")
        g = groups.setdefault(ip, {"src_ip": ip, "count": 0, "first_seen": None,
                                   "last_seen": None, "max_severity": "INFO",
                                   "techniques": {}, "statuses": {}, "types": {},
                                   "country": f.get("country", "Unknown"),
                                   "country_code": f.get("country_code", ""),
                                   "geo": f.get("geo", {}), "sample_id": f.get("finding_id")})
        g["count"] += 1
        ts = f.get("ts_epoch", 0)
        g["first_seen"] = ts if g["first_seen"] is None else min(g["first_seen"], ts)
        g["last_seen"] = ts if g["last_seen"] is None else max(g["last_seen"], ts)
        from_ord = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if from_ord.get(f.get("severity", "INFO"), 0) > from_ord.get(g["max_severity"], 0):
            g["max_severity"] = f.get("severity")
            g["sample_id"] = f.get("finding_id")
        for m in f.get("mitre", []):
            g["techniques"][m["technique"]] = m["name"]
        g["statuses"][f.get("status", "new")] = g["statuses"].get(f.get("status", "new"), 0) + 1
        g["types"][f.get("type", "?")] = g["types"].get(f.get("type", "?"), 0) + 1
    out = []
    for g in groups.values():
        g["techniques"] = [{"technique": k, "name": v} for k, v in g["techniques"].items()]
        g["open"] = g["statuses"].get("new", 0) + g["statuses"].get("investigating", 0)
        g["incident_id"] = g["src_ip"]
        out.append(g)
    out.sort(key=lambda x: (-{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                            .get(x["max_severity"], 0), -x["count"]))
    return resp(200, {"incidents": out, "count": len(out)})


def patch_incident(ip, body):
    status = (body or {}).get("status")
    if status not in STATUSES:
        return resp(400, {"error": "invalid status"})
    n = 0
    for f in recent(1000):
        if f.get("src_ip") == ip:
            _set_status(f["finding_id"], status)
            n += 1
    return resp(200, {"incident_id": ip, "status": status, "updated": n})


def stats(qs):
    items = [f for f in recent(1000) if _match(f, qs)]
    by_sev, by_type, by_status, by_country, by_ip = {}, {}, {}, {}, {}
    alerted = ack_total = ack_n = res_total = res_n = 0
    times = []
    for f in items:
        sev = f.get("severity", "?")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_type[f.get("type", "?")] = by_type.get(f.get("type", "?"), 0) + 1
        by_status[f.get("status", "new")] = by_status.get(f.get("status", "new"), 0) + 1
        c = f.get("country", "Unknown")
        by_country[c] = by_country.get(c, 0) + 1
        ip = f.get("src_ip", "?")
        by_ip[ip] = by_ip.get(ip, 0) + 1
        if f.get("alerted"):
            alerted += 1
        ts = _num(f.get("ts_epoch"))
        if ts:
            times.append(ts)
        if f.get("acknowledged_at") and ts:
            ack_total += _num(f["acknowledged_at"]) - ts
            ack_n += 1
        if f.get("resolved_at") and ts:
            res_total += _num(f["resolved_at"]) - ts
            res_n += 1

    # timeline: ~40 buckets across the observed window
    timeline = []
    if times:
        lo, hi = min(times), max(times)
        span = max(hi - lo, 1)
        step = max(span // 40, 30)
        buckets = {}
        for t in times:
            b = (t // step) * step
            buckets[b] = buckets.get(b, 0) + 1
        timeline = [{"t": k, "count": v} for k, v in sorted(buckets.items())]

    open_incidents = len({f.get("src_ip") for f in items
                          if f.get("status") in ("new", "investigating")})
    blocked = blocklist.scan(Select="COUNT").get("Count", 0)
    top_ips = sorted(by_ip.items(), key=lambda x: -x[1])[:8]
    return resp(200, {
        "total": len(items), "alerted": alerted, "open_incidents": open_incidents,
        "blocked": blocked,
        "by_severity": by_sev, "by_type": by_type, "by_status": by_status,
        "by_country": by_country,
        "top_sources": [{"src_ip": k, "count": v} for k, v in top_ips],
        "timeline": timeline,
        "mtta_seconds": round(ack_total / ack_n, 1) if ack_n else None,
        "mttr_seconds": round(res_total / res_n, 1) if res_n else None,
    })


def geo(qs):
    points = {}
    for f in recent(1000):
        if not _match(f, qs):
            continue
        g = f.get("geo") or {}
        lat, lon = g.get("lat"), g.get("lon")
        if lat in (None, 0) and lon in (None, 0):
            continue
        ip = f.get("src_ip")
        p = points.setdefault(ip, {"src_ip": ip, "lat": lat, "lon": lon,
                                   "country": f.get("country", "Unknown"),
                                   "city": g.get("city", ""), "count": 0,
                                   "max_severity": "INFO"})
        p["count"] += 1
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(f.get("severity", "INFO"), 0) > order.get(p["max_severity"], 0):
            p["max_severity"] = f.get("severity")
    return resp(200, {"points": list(points.values())})


def get_blocklist():
    items = blocklist.scan().get("Items", [])
    items.sort(key=lambda x: -_num(x.get("blocked_at")))
    return resp(200, {"blocked": items, "count": len(items)})


def add_block(body):
    ip = (body or {}).get("src_ip", "").strip()
    if not ip:
        return resp(400, {"error": "src_ip required"})
    blocklist.put_item(Item={"src_ip": ip, "blocked_at": int(time.time()),
                             "note": (body.get("note") or "")[:200], "by": "analyst"})
    return resp(200, {"src_ip": ip, "blocked": True})


def remove_block(ip):
    blocklist.delete_item(Key={"src_ip": ip})
    return resp(200, {"src_ip": ip, "blocked": False})


def handler(event, context):
    ctx = event.get("requestContext", {}).get("http", {})
    method = ctx.get("method", "GET")
    path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}
    parts = [p for p in path.split("/") if p]  # e.g. ["findings","abc"]
    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except json.JSONDecodeError:
            body = {}

    if method == "OPTIONS":
        return resp(200, {})

    try:
        head = parts[0] if parts else ""
        if head == "stats":
            return stats(qs)
        if head == "geo":
            return geo(qs)
        if head == "findings":
            if len(parts) == 1:
                return list_findings(qs)
            fid = parts[1]
            if method == "PATCH":
                return patch_finding(fid, body)
            return get_finding(fid, qs)
        if head == "incidents":
            if len(parts) == 1:
                return incidents(qs)
            if method == "PATCH":
                return patch_incident(parts[1], body)
            return resp(405, {"error": "method not allowed"})
        if head == "blocklist":
            if len(parts) == 1:
                if method == "POST":
                    return add_block(body)
                return get_blocklist()
            if method == "DELETE":
                return remove_block(parts[1])
            return resp(405, {"error": "method not allowed"})
    except Exception as e:  # noqa
        return resp(500, {"error": str(e)})
    return resp(404, {"error": "route not found", "path": path})
