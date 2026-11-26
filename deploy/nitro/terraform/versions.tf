# Klav Cloud's hosted proxy on AWS Nitro Enclaves (ADR 0051 §7.4). What
# this creates, and what it never holds, is in README.md.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State holds no secret of Klav's (no key exists anywhere in this stack),
  # but it names every resource: keep it in a private, versioned bucket.
  # Configure with `terraform init -backend-config=…` (README.md).
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "klav"
      Component = "hosted-proxy"
      ManagedBy = "terraform"
      Adr       = "0051"
    }
  }
}
