variable "region" {
  description = "AWS region (Learner Lab supports us-east-1 / us-west-2)"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "aegis"
}

variable "lab_role_name" {
  description = "Pre-existing execution role attached to all resources (Learner Lab)"
  type        = string
  default     = "LabRole"
}

variable "image_tag" {
  description = "Container image tag for the CloudJuice target"
  type        = string
  default     = "latest"
}

variable "container_port" {
  description = "Port the CloudJuice container listens on"
  type        = number
  default     = 8080
}

variable "alert_threshold" {
  description = "Minimum severity that triggers an SNS alert"
  type        = string
  default     = "HIGH"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "log_retention_days" {
  type    = number
  default = 7
}

variable "alert_email" {
  description = "Optional email address for high-severity alerts. When set, a confirmation email is sent once; click it to activate. Leave blank to disable email."
  type        = string
  default     = ""
}
