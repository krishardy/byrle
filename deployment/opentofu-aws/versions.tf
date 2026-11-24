# OpenTofu. `make opentofu-check` runs 1.13.9. The database password and the reverse proxy key
# are ephemeral values, sent to AWS through write-only arguments without entering the state.
# .terraform.lock.hcl records each provider's hashes for linux_amd64, linux_arm64,
# darwin_amd64 and darwin_arm64.
terraform {
  required_version = ">= 1.13"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.73.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.9.1"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = { Application = var.name }
  }
}
