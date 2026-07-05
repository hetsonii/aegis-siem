"""Ingestion Lambda.

Trigger: CloudWatch Logs subscription filter (the CloudJuice log group,
filtered to security events). Each invocation carries a gzip+base64 payload of
one or more log events. We normalize each into the common schema, archive the
raw record to the S3 lake, and enqueue the normalized event to SQS.
"""
import base64
import calendar
import gzip
import hashlib
import json
import os
import time
import boto3

s3 = boto3.client("s3")
sqs = boto3.client("sqs")

LAKE_BUCKET = os.environ["LAKE_BUCKET"]
QUEUE_URL = os.environ["QUEUE_URL"]


def _epoch(ts_iso):
    try:
        return calendar.timegm(time.strptime(ts_iso[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:  # noqa
        return int(time.time())


def normalize(raw, log_stream):
    event_id = hashlib.sha256(
        (json.dumps(raw, sort_keys=True) + log_stream).encode()).hexdigest()[:24]
    ts_iso = raw.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "event_id": event_id,
        "timestamp": ts_iso,
        "ts_epoch": _epoch(ts_iso),
        "source": raw.get("source", "cloudjuice-app"),
        "src_ip": raw.get("src_ip", "unknown"),
        "method": raw.get("method", ""),
        "path": raw.get("path", ""),
        "query": raw.get("query", ""),
        "user_agent": raw.get("user_agent", ""),
        "referer": raw.get("referer", ""),
        "signal": raw.get("signal"),
        "detail": raw.get("detail", {}),
        "raw_message": raw,
    }


def handler(event, context):
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {"skipped": "control"}

    log_stream = payload.get("logStream", "")
    ingested = 0
    for le in payload.get("logEvents", []):
        try:
            raw = json.loads(le["message"])
        except json.JSONDecodeError:
            continue
        norm = normalize(raw, log_stream)
        key = f"raw/dt={time.strftime('%Y/%m/%d')}/{norm['event_id']}.json"
        s3.put_object(Bucket=LAKE_BUCKET, Key=key,
                      Body=json.dumps(raw, default=str), ContentType="application/json")
        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(norm, default=str))
        ingested += 1
    return {"ingested": ingested}
