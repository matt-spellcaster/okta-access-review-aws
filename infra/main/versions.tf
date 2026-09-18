terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # terraform init -backend-config=backend.hcl   (see backend.hcl.example)
  backend "s3" {
    key          = "main/terraform.tfstate"
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "okta-access-review"
      ManagedBy = "terraform/main"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  prefix     = var.name_prefix
  # SecureString parameters. Terraform never creates or reads them (their values
  # would end up in state); set them once with aws ssm put-parameter.
  params = {
    okta_private_key     = "/uar/okta/private_key"
    slack_bot_token      = "/uar/slack/bot_token"
    slack_signing_secret = "/uar/slack/signing_secret"
    jira_api_token       = "/uar/jira/api_token"
  }
}
