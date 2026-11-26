# The parents' security group (ADR 0051 §1.2, §7.4). No port 22: the
# operator uses SSM Session Manager. Amazon DNS, the instance metadata
# service and Amazon Time Sync are not filtered by security groups.
#
#   in  443   the channel NLB (client address preserved): sandboxes
#   in  8443  the API NLB (client address preserved): devices, and a joining
#             enclave, which reaches proxy.klav.dev through its own parent's
#             egress and arrives from that parent's Elastic IP
#   in  8080  NLB health checks, from inside the VPC
#   out 443   only: the enclave's egress (api.klav.dev, providers, MCP
#             servers, raw.githubusercontent.com, proxy.klav.dev for a
#             hand-off), dnf and SSM

resource "aws_security_group" "parent" {
  name        = "${var.name}-parent"
  description = "Klav hosted proxy parents (ADR 0051)"
  vpc_id      = local.vpc_id
  tags        = { Name = "${var.name}-parent" }
}

resource "aws_vpc_security_group_ingress_rule" "channel" {
  for_each = toset(var.channel_ingress_cidrs)

  security_group_id = aws_security_group.parent.id
  description       = "Sandbox channels through the channel NLB (TLS terminated in the enclave)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "api" {
  for_each = toset(var.api_ingress_cidrs)

  security_group_id = aws_security_group.parent.id
  description       = "The API and the hand-off through the API NLB"
  ip_protocol       = "tcp"
  from_port         = 8443
  to_port           = 8443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "health" {
  security_group_id = aws_security_group.parent.id
  description       = "NLB health checks (GET /healthz)"
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = local.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.parent.id
  description       = "Egress on 443 only (the enclave's CONNECTs, dnf, SSM)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}
