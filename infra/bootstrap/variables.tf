variable "region" {
  description = "AWS region for everything in this account."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "uar"
}

variable "github_repo" {
  description = "GitHub repository allowed to deploy, as owner/name."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name."
  }
}

variable "github_owner_id" {
  description = "Numeric ID of the repository owner (gh api users/<owner> --jq .id)."
  type        = number
}

variable "github_repo_id" {
  description = "Numeric ID of the repository (gh api repos/<owner>/<name> --jq .id)."
  type        = number
}

variable "deploy_environment" {
  description = "GitHub environment whose jobs may assume the apply role. Protect it with required reviewers."
  type        = string
  default     = "production"
}
