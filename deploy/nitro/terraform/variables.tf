variable "region" {
  description = "AWS region, one near api.klav.dev (ADR 0051 Q7)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Prefix for every resource name. Changing it renames the IAM role, which changes PCR3 and so the manifest's parent_roles."
  type        = string
  default     = "klav-hosted-proxy"
}

variable "zones" {
  description = <<-EOT
    The parent instances, one per availability zone, keyed by a short name.
    `az_index` picks the zone from the region's available zones (or from
    `existing_subnet_ids`, by position).

    `in_service` attaches that parent to both load balancers. At most ONE
    zone is in service: the other runs a joined enclave that holds the seed
    but serves nobody (the standby). Two enclaves serving at once break
    sandboxes, because the hand-off is a snapshot and claims made on one are
    unknown to the other (ADR 0051 §16, "continuous replication" in the
    roadmap). Failing over or upgrading moves `in_service` from one zone to
    the other (runbook §6, §7).

    Removing a key destroys that instance and its enclave: never remove the
    last zone holding the seed.
  EOT
  type = map(object({
    az_index   = number
    in_service = bool
  }))
  default = {
    a = { az_index = 0, in_service = true }
    b = { az_index = 1, in_service = false }
  }

  validation {
    condition     = length(var.zones) <= 2 && alltrue([for z in values(var.zones) : z.az_index >= 0 && z.az_index <= 1])
    error_message = "At most two zones, with az_index 0 or 1 (ADR 0051 Q7: two c7g.large in two zones)."
  }

  validation {
    condition     = length([for z in values(var.zones) : z if z.in_service]) <= 1
    error_message = "At most one zone in service: two enclaves serving at once end sandboxes as theft until continuous replication exists (ADR 0051 §16)."
  }
}

variable "instance_type" {
  description = "Parent instance type. c7g.large is the smallest Graviton size Nitro Enclaves allow (ADR 0051 §7.4); the EIF is aarch64."
  type        = string
  default     = "c7g.large"

  validation {
    condition     = can(regex("^(c|m|r)[678]g[a-z]*\\.(large|[0-9]*xlarge)$", var.instance_type))
    error_message = "Use a Graviton type Nitro Enclaves support (not .medium or .metal): the EIF is aarch64."
  }
}

variable "ami_id" {
  description = "Parent AMI. Empty: the latest Amazon Linux 2023 arm64 at first apply (later AMI releases don't replace running instances)."
  type        = string
  default     = ""
}

variable "root_volume_gib" {
  description = "Encrypted gp3 root volume. It holds the OS, the bundle and nothing of value."
  type        = number
  default     = 20
}

variable "termination_protection" {
  description = "EC2 termination protection on both parents. Terminating both at once is a total loss (ADR 0051 §4.4): keep it on."
  type        = bool
  default     = true
}

variable "create_vpc" {
  description = "Create a VPC with two public subnets. false: use existing_vpc_id and existing_subnet_ids."
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR of the VPC this creates (create_vpc = true)."
  type        = string
  default     = "10.42.0.0/16"
}

variable "existing_vpc_id" {
  description = "With create_vpc = false: the VPC."
  type        = string
  default     = ""
}

variable "existing_subnet_ids" {
  description = "With create_vpc = false: two public subnets (a route to an internet gateway) in two zones, in az_index order."
  type        = list(string)
  default     = []
}

variable "channel_ingress_cidrs" {
  description = "Who may open sandbox channels (TCP 443, a<agent_id>.proxy.klav.dev). Sandboxes run anywhere, so the internet by default."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "api_ingress_cidrs" {
  description = "Who may reach the API (proxy.klav.dev: devices, and a joining enclave through its parent's Elastic IP). The client's address is preserved for the parent's per-IP limit, so this is the internet by default."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "api_domain" {
  description = "The proxy's name: the API at https://<this>/ and each account's channel at a<agent_id>.<this> (the enclave's KLAV_ENCLAVE_ENDPOINT, baked into the image)."
  type        = string
  default     = "proxy.klav.dev"
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone of api_domain's parent. Empty: create the DNS records by hand from the outputs (klav.dev's DNS lives outside AWS)."
  type        = string
  default     = ""
}

variable "deregistration_delay_seconds" {
  description = "How long a target being drained keeps its open connections (runbook §6)."
  type        = number
  default     = 60
}

variable "alarm_actions" {
  description = "ARNs notified by the alarms (an SNS topic). Empty: alarms change state but notify nobody."
  type        = list(string)
  default     = []
}

variable "auto_recover" {
  description = "Recover a parent automatically when AWS's system status check fails. The recovered enclave joins again from the zone in service (klav-enclave.service)."
  type        = bool
  default     = true
}
