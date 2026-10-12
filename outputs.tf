output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key"
  value       = aws_kms_key.main.arn
}

output "audit_log_bucket" {
  description = "S3 bucket holding CloudTrail logs"
  value       = aws_s3_bucket.logs.id
}

output "app_data_bucket" {
  description = "Encrypted application data bucket"
  value       = aws_s3_bucket.app_data.id
}

output "app_role_arn" {
  description = "ARN of the least-privilege application role"
  value       = aws_iam_role.app.arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF web ACL (associate with an ALB or API Gateway stage)"
  value       = aws_wafv2_web_acl.main.arn
}
