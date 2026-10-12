# AWS Security Baseline with Terraform

A small, reusable security baseline for an AWS account, written as Terraform. It shows encryption at rest and in transit, least-privilege IAM, audit logging with CloudTrail, alerting with CloudWatch and a WAF web ACL.

## What it builds

| Area | Resource | Why it matters |
| --- | --- | --- |
| Encryption at rest | Customer-managed KMS key with automatic rotation; S3 buckets encrypted with it (SSE-KMS) | Data is encrypted on disk and the key is under your control |
| Encryption in transit | Bucket policies that deny any request not using TLS (`aws:SecureTransport = false`) | Prevents unencrypted access to data |
| Data protection | S3 public access block on every bucket, versioning on the log bucket | Stops accidental public exposure |
| IAM | EC2 role that can only read objects from one bucket and decrypt with one key | Least privilege: a compromised app cannot reach anything else |
| Audit | Multi-region CloudTrail with log file validation, delivered to S3 and CloudWatch Logs, encrypted with KMS | A tamper-evident record of every API call |
| Monitoring | CloudWatch metric filter and alarm for unauthorised or access-denied API calls, with SNS notification | Detects probing and misconfiguration quickly |
| Web protection | WAFv2 web ACL with AWS managed Common and SQL injection rule sets plus a per-IP rate limit | Blocks common web attacks and abusive clients |

## Usage

Requires Terraform 1.5 or newer and AWS credentials with permission to create these resources.

```bash
terraform init
terraform plan -var="alert_email=you@example.com"
terraform apply -var="alert_email=you@example.com"
```

Confirm the SNS subscription email that AWS sends so alarms reach you.

To protect an application, associate the WAF web ACL with an Application Load Balancer or API Gateway stage (`aws_wafv2_web_acl_association`).

## Clean up

```bash
terraform destroy
```

CloudTrail, KMS, CloudWatch Logs and WAF can incur small charges, so destroy the stack when you finish experimenting.

## Design notes

- The audit log bucket policy allows only CloudTrail to write, scoped to this account, and denies non-TLS traffic.
- The application role gets `s3:GetObject` on one bucket, `s3:ListBucket` on the same bucket and `kms:Decrypt` on one key. Nothing else.
- Log retention is set to 90 days in CloudWatch. Raise it if your compliance needs are longer.
- The WAF is created but not attached, because attaching depends on which load balancer or API you run.

## Skills shown

AWS IAM, KMS, S3 security, encryption at rest and in transit, CloudTrail, CloudWatch alarms, AWS WAF, SNS, Terraform.
