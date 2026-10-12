variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-1"
}

variable "project" {
  description = "Name prefix used on all resources (lowercase letters, numbers, hyphens)"
  type        = string
  default     = "secdemo"
}

variable "alert_email" {
  description = "Email address for security alarm notifications (leave empty to skip the subscription)"
  type        = string
  default     = ""
}

variable "rate_limit" {
  description = "Maximum requests per IP in a 5-minute window before the WAF blocks it"
  type        = number
  default     = 1000
}
