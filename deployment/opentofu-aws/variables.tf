variable "region" {
  description = "The AWS region."
  type        = string
}

variable "name" {
  description = "The prefix of every resource's name."
  type        = string
  default     = "byrle"
}

variable "byrle_image" {
  description = "The release image by digest: ghcr.io/krishardy/byrle:<version>@sha256:<digest>, after verifying it as docs/runbook.md says."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.byrle_image))
    error_message = "byrle_image must end in @sha256:<digest>."
  }
}

variable "proxy_url" {
  description = "The load balancer's address as installing machines reach it, such as https://byrle.example.com. Lockfiles record it."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+", var.proxy_url))
    error_message = "proxy_url must begin https://."
  }
}

variable "certificate_arn" {
  description = "The ACM certificate for proxy_url's name, in this region."
  type        = string
}

variable "route53_zone_id" {
  description = "The Route 53 hosted zone to add proxy_url's name to, as an alias of the load balancer. Empty adds no record."
  type        = string
  default     = ""
}

variable "allowed_cidrs" {
  description = "The addresses that may reach the load balancer on 443."
  type        = list(string)
}

variable "mode" {
  description = "BYRLE_MODE. \"observe\" for the first week; \"\" to enforce."
  type        = string
  default     = "observe"
}

variable "policy_file" {
  description = "The policy file, relative to this directory."
  type        = string
  default     = "policy.yaml"
}

variable "github_token_secret_arn" {
  description = "A Secrets Manager secret holding a GitHub token, for GitHub's Advisory Database. Empty runs without one."
  type        = string
  default     = ""
}

variable "environment" {
  description = "Any other setting `byrle --help` lists, as NAME = value."
  type        = map(string)
  default     = {}
}

variable "architecture" {
  description = "The Fargate CPU architecture: ARM64 or X86_64."
  type        = string
  default     = "ARM64"
}

variable "cpu" {
  description = "The proxy task's CPU units."
  type        = number
  default     = 1024
}

variable "memory" {
  description = "The proxy task's memory, in MiB."
  type        = number
  default     = 2048
}

variable "refresh_schedule" {
  description = "When EventBridge Scheduler runs `byrle refresh`, in UTC."
  type        = string
  default     = "cron(0 0/6 * * ? *)"
}

variable "vpc_cidr" {
  description = "The new VPC's address range."
  type        = string
  default     = "10.40.0.0/16"
}

variable "db_instance_class" {
  description = "The RDS instance class."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "The RDS Postgres version. A major version alone takes its minor upgrades."
  type        = string
  default     = "18"
}

variable "db_allocated_storage" {
  description = "The database's storage at creation, in GiB."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage" {
  description = "The size RDS may grow the storage to, in GiB."
  type        = number
  default     = 100
}

variable "db_multi_az" {
  description = "A standby database in a second availability zone."
  type        = bool
  default     = false
}

variable "db_password_version" {
  description = "Raise by one to generate a new database password. The proxy reads it when its tasks start."
  type        = number
  default     = 1
}

variable "rp_key_version" {
  description = "Raise by one to generate a new BYRLE_RP_KEY."
  type        = number
  default     = 1
}

variable "deletion_protection" {
  description = "Refuse to delete the database and the load balancer."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "How long CloudWatch keeps the containers' output."
  type        = number
  default     = 30
}
