# Allow CloudWatch Logs to invoke the ingestion Lambda.
resource "aws_lambda_permission" "logs_invoke_ingestion" {
  statement_id  = "AllowCWLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingestion.function_name
  principal     = "logs.${var.region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.ecs.arn}:*"
}

# Forward ONLY security events (JSON filter) to ingestion for low-latency detection.
resource "aws_cloudwatch_log_subscription_filter" "security" {
  name            = "${local.prefix}-security-events"
  log_group_name  = aws_cloudwatch_log_group.ecs.name
  filter_pattern  = "{ $.event_type = \"security\" }"
  destination_arn = aws_lambda_function.ingestion.arn

  depends_on = [aws_lambda_permission.logs_invoke_ingestion]
}
