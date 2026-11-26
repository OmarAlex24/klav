# Alarms (runbook §9):
#   - no healthy target: the zone in service is down, so the hosted proxy is
#     down for everyone (sandboxes get klav_proxy_unreachable). Fail over to
#     the standby (runbook §7) before anything else.
#   - an unhealthy target: the parent in service fails its health check.
#   - a parent's status check: a host problem, in service or standby; the
#     system check recovers the instance automatically (auto_recover), and
#     its enclave joins again from the zone in service.
# NOT covered: the standby's enclave. It is attached to no load balancer, so
# nothing here sees whether it holds the seed; klav-enclave.service is a
# oneshot that stays "active" even after a failed join. Check it after every
# change and daily (runbook §9). Losing the standby unnoticed turns the next
# failure of the zone in service into a total loss (ADR 0051 §4.4).

locals {
  target_groups = {
    channel = { tg = aws_lb_target_group.channel, lb = aws_lb.channel }
    api     = { tg = aws_lb_target_group.api, lb = aws_lb.api }
  }
}

resource "aws_cloudwatch_metric_alarm" "no_healthy_target" {
  for_each = local.target_groups

  alarm_name          = "${var.name}-${each.key}-no-healthy-target"
  alarm_description   = "Klav hosted proxy: no healthy ${each.key} target. Every sandbox call fails. Fail over to the standby: runbook §7."
  namespace           = "AWS/NetworkELB"
  metric_name         = "HealthyHostCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    TargetGroup  = each.value.tg.arn_suffix
    LoadBalancer = each.value.lb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_target" {
  for_each = local.target_groups

  alarm_name          = "${var.name}-${each.key}-unhealthy-target"
  alarm_description   = "Klav hosted proxy: the ${each.key} target in service is unhealthy. Runbook §7, §9."
  namespace           = "AWS/NetworkELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    TargetGroup  = each.value.tg.arn_suffix
    LoadBalancer = each.value.lb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "status_check" {
  for_each = var.zones

  alarm_name          = "${var.name}-${each.key}-status-check-failed"
  alarm_description   = "Klav hosted proxy parent ${each.key}: an EC2 status check failed. Runbook §9."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    InstanceId = aws_instance.parent[each.key].id
  }
}

resource "aws_cloudwatch_metric_alarm" "system_recover" {
  for_each = var.auto_recover ? var.zones : {}

  alarm_name          = "${var.name}-${each.key}-system-recover"
  alarm_description   = "Klav hosted proxy parent ${each.key}: AWS's system check failed; recovering the instance. Its enclave joins again from the zone in service (if this was the zone in service, fail over first: runbook §7)."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  alarm_actions       = concat(["arn:${data.aws_partition.current.partition}:automate:${var.region}:ec2:recover"], var.alarm_actions)

  dimensions = {
    InstanceId = aws_instance.parent[each.key].id
  }
}
