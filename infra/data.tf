data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# Learner Lab pre-creates this role; we attach it everywhere instead of
# creating roles (role creation is not permitted).
data "aws_iam_role" "lab" {
  name = var.lab_role_name
}

# Regional account id that ALB uses to deliver access logs.
data "aws_elb_service_account" "main" {}

locals {
  prefix     = var.project
  account_id = data.aws_caller_identity.current.account_id
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)

  lake_bucket    = "${var.project}-lake-${local.account_id}"
  alb_log_bucket = "${var.project}-alb-logs-${local.account_id}"
  trail_bucket   = "${var.project}-trail-${local.account_id}"
  spa_bucket     = "${var.project}-console-${local.account_id}"

  lab_role_arn = data.aws_iam_role.lab.arn
}
