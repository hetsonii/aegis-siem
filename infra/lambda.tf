locals {
  lambda_src = "${path.module}/.."
}

# ---- packaging ------------------------------------------------------------
data "archive_file" "ingestion" {
  type        = "zip"
  source_dir  = "${local.lambda_src}/lambdas/ingestion"
  output_path = "${path.module}/build/ingestion.zip"
}

data "archive_file" "detection" {
  type        = "zip"
  source_dir  = "${local.lambda_src}/lambdas/detection"
  output_path = "${path.module}/build/detection.zip"
}

data "archive_file" "alert" {
  type        = "zip"
  source_dir  = "${local.lambda_src}/lambdas/alert"
  output_path = "${path.module}/build/alert.zip"
}

data "archive_file" "dashboard" {
  type        = "zip"
  source_dir  = "${local.lambda_src}/lambdas/dashboard_api"
  output_path = "${path.module}/build/dashboard.zip"
}

# ---- log groups -----------------------------------------------------------
# NOTE: we intentionally do NOT declare aws_cloudwatch_log_group for the Lambda
# functions. AWS Lambda auto-creates /aws/lambda/<name> on first invocation, and
# if Terraform also owns that name, a single post-destroy invocation (e.g. a
# stray request to the public API) recreates the group outside state, which then
# blocks every future `apply` with "log group already exists". Letting Lambda own
# its own log group makes destroy/apply fully repeatable. The ECS log group is
# still managed here because the CloudWatch Logs subscription filter must attach
# to a group that already exists at apply time.
#
# Lambda log retention (optional) can be set after apply without re-introducing
# the collision, e.g.:
#   aws logs put-retention-policy --log-group-name /aws/lambda/aegis-detection --retention-in-days 7

# ---- functions ------------------------------------------------------------
resource "aws_lambda_function" "ingestion" {
  function_name    = "${local.prefix}-ingestion"
  role             = local.lab_role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.ingestion.output_path
  source_code_hash = data.archive_file.ingestion.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      LAKE_BUCKET = aws_s3_bucket.lake.id
      QUEUE_URL   = aws_sqs_queue.main.id
    }
  }
  tracing_config { mode = "Active" }
}

resource "aws_lambda_function" "detection" {
  function_name    = "${local.prefix}-detection"
  role             = local.lab_role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.detection.output_path
  source_code_hash = data.archive_file.detection.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      STATE_TABLE     = aws_dynamodb_table.state.name
      LAKE_BUCKET     = aws_s3_bucket.lake.id
      TOPIC_ARN       = aws_sns_topic.alerts.arn
      ALERT_THRESHOLD = var.alert_threshold
    }
  }
  tracing_config { mode = "Active" }
}

resource "aws_lambda_function" "alert" {
  function_name    = "${local.prefix}-alert"
  role             = local.lab_role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.alert.output_path
  source_code_hash = data.archive_file.alert.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }
  tracing_config { mode = "Active" }
}

resource "aws_lambda_function" "dashboard" {
  function_name    = "${local.prefix}-dashboard"
  role             = local.lab_role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.dashboard.output_path
  source_code_hash = data.archive_file.dashboard.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      BLOCKLIST_TABLE = aws_dynamodb_table.blocklist.name
      LAKE_BUCKET     = aws_s3_bucket.lake.id
    }
  }
  tracing_config { mode = "Active" }
}

# ---- SQS -> detection -----------------------------------------------------
resource "aws_lambda_event_source_mapping" "sqs_detection" {
  event_source_arn = aws_sqs_queue.main.arn
  function_name    = aws_lambda_function.detection.arn
  batch_size       = 10
  enabled          = true
}
