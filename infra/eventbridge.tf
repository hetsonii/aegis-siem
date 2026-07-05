# Scheduled correlation sweep - catches slow patterns (e.g. drawn-out brute
# force) that per-event detection would miss.
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.prefix}-correlation-scan"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "detection" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "detection"
  arn       = aws_lambda_function.detection.arn
  input     = jsonencode({ scan = "scheduled" })
}

resource "aws_lambda_permission" "events_invoke_detection" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
