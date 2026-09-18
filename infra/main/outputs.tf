output "slack_request_url" {
  description = "Paste into the Slack app's Interactivity Request URL (slack/manifest.yaml)."
  value       = aws_lambda_function_url.interact.function_url
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.bucket
}

output "work_bucket" {
  value = aws_s3_bucket.work.bucket
}

output "state_machine_arn" {
  value = aws_sfn_state_machine.review.arn
}

output "secret_parameters" {
  description = "SecureString parameters to set once with aws ssm put-parameter (Terraform never holds their values)."
  value       = values(local.params)
}
