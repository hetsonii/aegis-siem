# Findings / cases - the analyst working set.
resource "aws_dynamodb_table" "findings" {
  name         = "${local.prefix}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "gsi_pk"
    type = "S"
  }
  attribute {
    name = "created_at"
    type = "S"
  }

  # list-recent access pattern: single partition, sorted by ISO timestamp
  global_secondary_index {
    name            = "by_time"
    hash_key        = "gsi_pk"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  server_side_encryption { enabled = true }
  point_in_time_recovery { enabled = true }
}

# Detection state - sliding-window counters, expired automatically by TTL.
resource "aws_dynamodb_table" "state" {
  name         = "${local.prefix}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "state_key"

  attribute {
    name = "state_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption { enabled = true }
}

# Blocklist - sources the SOC has blocked. The honeypot polls this over HTTP
# and returns 403 to listed sources; the console removes entries to unblock.
resource "aws_dynamodb_table" "blocklist" {
  name         = "${local.prefix}-blocklist"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "src_ip"

  attribute {
    name = "src_ip"
    type = "S"
  }

  server_side_encryption { enabled = true }
}
