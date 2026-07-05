# Control-plane audit log. Delivered to S3 only: Learner Lab does not permit
# enabling CloudWatch Logs delivery on a trail, so we omit that integration.
resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}
