# Network-layer telemetry. S3 delivery needs no IAM role (unlike CloudWatch
# Logs delivery), which suits the Learner Lab no-role-creation constraint.
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.lake.arn

  depends_on = [aws_s3_bucket_policy.lake]
}
