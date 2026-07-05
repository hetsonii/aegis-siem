resource "aws_sqs_queue" "dlq" {
  name                      = "${local.prefix}-events-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "main" {
  name                       = "${local.prefix}-events"
  sqs_managed_sse_enabled    = true
  visibility_timeout_seconds = 180 # >= detection Lambda timeout
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sns_topic" "alerts" {
  name = "${local.prefix}-alerts"
}
