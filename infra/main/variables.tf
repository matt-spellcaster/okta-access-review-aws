variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "uar"
}

variable "image_digest" {
  description = "Digest of the Lambda image in this stack's ECR repository (sha256:...). CI passes the one it just pushed."
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be sha256:<64 hex characters>."
  }
}

variable "teardown_role_arn" {
  description = "The bootstrap apply role. The only principal allowed to bypass evidence retention (teardown only)."
  type        = string
}

# --- Okta (non-secret) ---

variable "okta_org_url" {
  type = string
}

variable "okta_client_id" {
  type = string
}

variable "okta_key_id" {
  type = string
}

# --- Slack (non-secret) ---

variable "slack_channel_id" {
  description = "Private review channel for counts-only posts."
  type        = string
}

variable "slack_admin_user" {
  description = "Slack user ID of the admin who reviews everything."
  type        = string
}

variable "slack_ciso_user" {
  description = "Slack user ID of the CISO: reviews the admin's own access, signs off, receives escalations."
  type        = string
}

# --- Jira Service Management (non-secret) ---

variable "jira_base_url" {
  type = string
}

variable "jira_email" {
  description = "Email of the Jira service account that owns the API token."
  type        = string
  sensitive   = true
}

variable "jira_project" {
  type = string
}

variable "jira_parent_type" {
  type    = string
  default = "Task"
}

variable "jira_child_type" {
  type    = string
  default = "Subtask"
}

# --- timing ---

variable "review_days" {
  type    = number
  default = 7
}

variable "leaver_ticket_hours" {
  type    = number
  default = 24
}

variable "revoke_ticket_days" {
  type    = number
  default = 7
}

variable "signoff_timeout_days" {
  description = "How long the review execution waits for the CISO's sign-off before it stops."
  type        = number
  default     = 30
}

variable "review_schedule" {
  description = "When quarterly reviews start (EventBridge Scheduler cron)."
  type        = string
  default     = "cron(0 9 15 1,4,7,10 ? *)"
}

variable "schedule_timezone" {
  type    = string
  default = "America/Chicago"
}

# --- retention and cost ---

variable "evidence_retention_days" {
  description = "Object Lock (governance) retention for review evidence; objects are deleted automatically afterwards."
  type        = number
  default     = 1095
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "budget_limit_usd" {
  type    = number
  default = 5
}

variable "budget_email" {
  description = "Where AWS Budgets sends cost alerts."
  type        = string
  sensitive   = true
}
