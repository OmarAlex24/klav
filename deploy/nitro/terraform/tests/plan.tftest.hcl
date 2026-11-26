# Plan-only checks with a mocked AWS provider: no credentials, no account,
# nothing created. `terraform init -backend=false && terraform test`.

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b", "us-east-1c"]
    }
  }

  mock_data "aws_ssm_parameter" {
    defaults = {
      value = "ami-0123456789abcdef0"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

run "one_serving_one_standby_by_default" {
  command = plan

  assert {
    condition     = length(aws_instance.parent) == 2
    error_message = "Two parents by default."
  }

  assert {
    condition     = alltrue([for i in aws_instance.parent : i.instance_type == "c7g.large"])
    error_message = "c7g.large parents."
  }

  assert {
    condition     = alltrue([for i in aws_instance.parent : i.enclave_options[0].enabled])
    error_message = "Nitro Enclaves on."
  }

  assert {
    condition     = alltrue([for i in aws_instance.parent : i.metadata_options[0].http_tokens == "required"])
    error_message = "IMDSv2 only."
  }

  assert {
    condition     = alltrue([for i in aws_instance.parent : i.root_block_device[0].encrypted])
    error_message = "Encrypted root volumes."
  }

  assert {
    condition     = aws_subnet.public[0].availability_zone != aws_subnet.public[1].availability_zone
    error_message = "Two zones."
  }

  assert {
    condition     = aws_lb_target_group.channel.preserve_client_ip == "true" && aws_lb_listener.channel.protocol == "TCP"
    error_message = "The channel is TCP passthrough with the client's address."
  }

  assert {
    condition     = keys(aws_lb_target_group_attachment.channel) == ["a"] && keys(aws_lb_target_group_attachment.api) == ["a"]
    error_message = "Only zone a serves; zone b is the standby."
  }

  assert {
    condition     = aws_lb_target_group.api.preserve_client_ip == "true"
    error_message = "The API keeps the client's address for the parent's per-IP limit."
  }

  assert {
    condition = alltrue([
      for r in aws_vpc_security_group_ingress_rule.channel : r.from_port == 443
      ]) && alltrue([
      for r in aws_vpc_security_group_ingress_rule.api : r.from_port == 8443
    ]) && aws_vpc_security_group_ingress_rule.health.from_port == 8080
    error_message = "Ingress only on 443, 8443 and 8080."
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.https.from_port == 443 && aws_vpc_security_group_egress_rule.https.to_port == 443
    error_message = "Egress on 443 only."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ssm.policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "The role has SSM only."
  }
}

run "fail_over_to_b" {
  command = plan

  variables {
    zones = {
      a = { az_index = 0, in_service = false }
      b = { az_index = 1, in_service = true }
    }
  }

  assert {
    condition     = length(aws_instance.parent) == 2
    error_message = "The drained parent keeps running."
  }

  assert {
    condition     = keys(aws_lb_target_group_attachment.channel) == ["b"] && keys(aws_lb_target_group_attachment.api) == ["b"]
    error_message = "Only the parent in service receives traffic."
  }
}

run "never_two_in_service" {
  command = plan

  variables {
    zones = {
      a = { az_index = 0, in_service = true }
      b = { az_index = 1, in_service = true }
    }
  }

  expect_failures = [var.zones]
}

run "no_third_zone" {
  command = plan

  variables {
    zones = {
      a = { az_index = 0, in_service = true }
      b = { az_index = 1, in_service = true }
      c = { az_index = 2, in_service = true }
    }
  }

  expect_failures = [var.zones]
}

run "route53_records_when_zone_given" {
  command = plan

  variables {
    route53_zone_id = "Z0123456789ABCDEFGHIJ"
  }

  assert {
    condition     = length(aws_route53_record.api) == 1 && aws_route53_record.channel[0].name == "*.proxy.klav.dev"
    error_message = "API and wildcard channel records."
  }
}
