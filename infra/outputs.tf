output "cloudjuice_url" {
  description = "Public URL of the CloudJuice target - point the attack script here"
  value       = "http://${aws_lb.main.dns_name}"
}

output "console_url" {
  description = "SOC console (static site) URL"
  value       = "http://${aws_s3_bucket_website_configuration.spa.website_endpoint}"
}

output "api_base" {
  description = "Dashboard API base URL"
  value       = aws_apigatewayv2_api.http.api_endpoint
}

output "ecr_repository_url" {
  description = "Push the CloudJuice image here"
  value       = aws_ecr_repository.cloudjuice.repository_url
}

output "lake_bucket" {
  value = aws_s3_bucket.lake.id
}

output "cloudwatch_dashboard" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}
