# Terraform 1.11 or OpenTofu 1.11, the first releases with write-only arguments: the database
# password and the reverse proxy key are generated and sent to AWS without entering the state.
terraform {
  required_version = ">= 1.11"

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
