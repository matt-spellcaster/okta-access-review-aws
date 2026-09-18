terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # The very first apply ran with this block commented out (the bucket didn't
  # exist yet), then moved its state here with
  #   terraform init -backend-config=backend.hcl -migrate-state
  # To tear down, comment it out again and migrate back first (docs/teardown.md).
  backend "s3" {
    key          = "bootstrap/terraform.tfstate"
    use_lockfile = true
    encrypt      = true
  }
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
