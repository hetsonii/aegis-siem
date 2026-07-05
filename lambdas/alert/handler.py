"""Alert Lambda.

Trigger: SNS (high-severity findings). Records the alert against the finding so
the SOC console can highlight it. Using SNS -> Lambda avoids the manual email
subscription confirmation step, keeping the deploy free of human intervention.
"""
import json
import os
import time
import boto3

ddb = boto3.resource("dynamodb")
findings = ddb.Table(os.environ["FINDINGS_TABLE"])


def handler(event, context):
    updated = 0
    for record in event.get("Records", []):
        try:
            msg = json.loads(record["Sns"]["Message"])
            fid = msg.get("finding", {}).get("finding_id") or msg["finding_id"]
        except (KeyError, json.JSONDecodeError):
            continue
        findings.update_item(
            Key={"finding_id": fid},
            UpdateExpression="SET alerted = :t, alerted_at = :ts",
            ExpressionAttributeValues={":t": True,
                                       ":ts": int(time.time())},
        )
        updated += 1
    return {"alerted": updated}
