# Two public subnets in two zones (ADR 0051 Q3, Q7). Public, because each
# parent's Elastic IP is the hosted proxy's fixed egress address, listed in
# the manifest for ADR 0044's strict network profile: a NAT gateway would
# add a cost and a shared single point for no gain.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  count = var.create_vpc ? 2 : 0

  vpc_id                  = aws_vpc.this[0].id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  count = var.create_vpc ? 2 : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# The VPC's default security group allows nothing.
resource "aws_default_security_group" "this" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.this[0].id
  tags   = { Name = "${var.name}-default-deny" }
}

data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  id    = var.existing_vpc_id
}

locals {
  vpc_id     = var.create_vpc ? aws_vpc.this[0].id : var.existing_vpc_id
  vpc_cidr   = var.create_vpc ? var.vpc_cidr : data.aws_vpc.existing[0].cidr_block
  subnet_ids = var.create_vpc ? aws_subnet.public[*].id : var.existing_subnet_ids
}

resource "terraform_data" "existing_network_check" {
  count = var.create_vpc ? 0 : 1

  lifecycle {
    precondition {
      condition     = var.existing_vpc_id != "" && length(var.existing_subnet_ids) == 2
      error_message = "With create_vpc = false, set existing_vpc_id and two existing_subnet_ids (public, in two zones)."
    }
  }
}
