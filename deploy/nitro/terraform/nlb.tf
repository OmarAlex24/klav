# Two Network Load Balancers, because both names are on port 443 and an NLB
# routes by port, not by name:
#
#   *.proxy.klav.dev  -> channel NLB, TCP 443 passthrough -> parent 443 ->
#                        enclave. TLS (raw Ed25519 keys, RFC 7250) ends in
#                        the enclave, which reads the SNI to pick the
#                        account's key (ADR 0051 §3.4). The NLB sees bytes.
#   proxy.klav.dev    -> API NLB, TLS 443 with an ACM certificate -> parent
#                        8443 -> enclave (plain HTTP): /v1/manifest,
#                        /v1/attest, /v1/enroll, /v1/status and the
#                        hand-off. The API is self-authenticating
#                        (attestation documents, the signed manifest, signed
#                        enrolls), so its transport is not trusted (ADR 0051
#                        §2.2 step 1); TLS here only keeps it private on
#                        the wire. A joining enclave uses it too: its image
#                        joins https://proxy.klav.dev, which reaches the one
#                        enclave in service.
#
# Only the zone in service is attached (var.zones). Cross-zone load
# balancing is on, so both NLB nodes reach it. Both target groups preserve
# the client's address, which the parent's per-IP limit needs (it is one
# limiter for both listeners). Both share one health check, the parent's
# GET /healthz on 8080, which is 200 once the enclave accepts a connection,
# before it has a seed: attach a parent only after its enclave answers
# GET /v1/manifest with 200 (runbook §3).

resource "aws_lb" "channel" {
  name                             = "${var.name}-channel"
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = local.subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.termination_protection
}

resource "aws_lb_target_group" "channel" {
  name                 = "${var.name}-channel"
  port                 = 443
  protocol             = "TCP"
  target_type          = "instance"
  vpc_id               = local.vpc_id
  preserve_client_ip   = true # the parent's per-IP limit (ADR 0051 §3.3)
  deregistration_delay = var.deregistration_delay_seconds

  health_check {
    protocol            = "HTTP"
    port                = "8080"
    path                = "/healthz"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "channel" {
  load_balancer_arn = aws_lb.channel.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.channel.arn
  }
}

resource "aws_lb" "api" {
  name                             = "${var.name}-api"
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = local.subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.termination_protection
}

resource "aws_lb_target_group" "api" {
  name                 = "${var.name}-api"
  port                 = 8443
  protocol             = "TCP"
  target_type          = "instance"
  vpc_id               = local.vpc_id
  preserve_client_ip   = true # the parent's per-IP limit (ADR 0051 §3.3)
  deregistration_delay = var.deregistration_delay_seconds

  health_check {
    protocol            = "HTTP"
    port                = "8080"
    path                = "/healthz"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.api.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# Only the parent in service receives traffic. The standby keeps running
# with the seed, outside both load balancers (runbook §6, §7). A joining
# enclave must never be attached before it joins: with the client address
# preserved, its own CONNECT to proxy.klav.dev could be routed back to it.
resource "aws_lb_target_group_attachment" "channel" {
  for_each = { for k, z in var.zones : k => z if z.in_service }

  target_group_arn = aws_lb_target_group.channel.arn
  target_id        = aws_instance.parent[each.key].id
  port             = 443
}

resource "aws_lb_target_group_attachment" "api" {
  for_each = { for k, z in var.zones : k => z if z.in_service }

  target_group_arn = aws_lb_target_group.api.arn
  target_id        = aws_instance.parent[each.key].id
  port             = 8443
}
