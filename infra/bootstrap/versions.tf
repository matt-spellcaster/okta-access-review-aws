terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # First apply uses local state (this bucket doesn't exist yet). Then fill in
  # backend.hcl (see backend.hcl.example), uncomment this block and run
  #   terraform init -backend-config=backend.hcl -migrate-state
  # backend "s3" {
  #   key          = "bootstrap/terraform.tfstate"
  #   use_lockfile = true
  #   encrypt      = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "okta-access-review"
      ManagedBy = "terraform/bootstrap"
    }
  }
}
