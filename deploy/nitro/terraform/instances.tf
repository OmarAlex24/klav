# Two c7g.large parents, one per zone (ADR 0051 Q7), each with an enclave
# of 1 vCPU and 2 GiB (deploy/nitro/parent/allocator.yaml). user_data only
# prepares the host (nitro-cli, the allocator); the bundle (parent binary,
# units, EIFs) is installed by the operator over SSM (runbook §3), because
# which image runs where is a release decision, not an infrastructure one.

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

locals {
  ami_id = var.ami_id != "" ? var.ami_id : nonsensitive(data.aws_ssm_parameter.al2023_arm64.value)
}

resource "aws_instance" "parent" {
  for_each = var.zones

  ami                     = local.ami_id
  instance_type           = var.instance_type
  subnet_id               = local.subnet_ids[each.value.az_index]
  vpc_security_group_ids  = [aws_security_group.parent.id]
  iam_instance_profile    = aws_iam_instance_profile.parent.name
  disable_api_termination = var.termination_protection
  ebs_optimized           = true
  monitoring              = true

  enclave_options {
    enabled = true
  }

  # IMDSv2 only, one hop: a container or the enclave's egress (which the
  # parent refuses for 169.254.0.0/16 anyway) can't reach it.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gib
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    nitro_cli_version = "1.5.3-0.amzn2023"
  })
  user_data_replace_on_change = false

  tags = { Name = "${var.name}-${each.key}" }

  lifecycle {
    # A new AMI or user_data never replaces a running parent: replacing one
    # restarts its enclave (runbook §6 does that on purpose, one at a time).
    ignore_changes = [ami, user_data]
  }
}

# The fixed egress addresses (the manifest's `egress`, ADR 0044's strict
# network profile).
resource "aws_eip" "parent" {
  for_each = var.zones

  domain   = "vpc"
  instance = aws_instance.parent[each.key].id
  tags     = { Name = "${var.name}-${each.key}" }
}
