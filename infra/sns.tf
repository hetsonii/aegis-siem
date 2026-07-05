# SNS -> Lambda avoids the manual email-subscription confirmation click,
# keeping the deploy fully automated.
resource "aws_lambda_permission" "sns_invoke_alert" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_subscription" "alert_lambda" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.alert.arn

  depends_on = [aws_lambda_permission.sns_invoke_alert]
}

# Optional human email notifications (in addition to the Lambda subscription).
# Set alert_email in terraform.tfvars / .env. AWS sends a one-time confirmation
# email that must be clicked once to activate - unavoidable for SNS email.
resource "aws_sns_topic_subscription" "alert_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
