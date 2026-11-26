# The API's certificate and, if klav.dev's zone is in Route 53, the records.
# Otherwise (klav.dev's DNS lives outside AWS) create by hand the records in
# the outputs `acm_validation_records` and `dns_records`; `terraform apply`
# waits for the certificate until the validation record exists.

resource "aws_acm_certificate" "api" {
  domain_name       = var.api_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  acm_validation = {
    for o in aws_acm_certificate.api.domain_validation_options : o.domain_name => {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  }
  manage_dns = var.route53_zone_id != ""
}

# Keyed by the configured name, which is known at plan time; the record's
# name and value are the certificate's, known only after it exists.
resource "aws_route53_record" "acm_validation" {
  for_each = local.manage_dns ? toset([var.api_domain]) : toset([])

  zone_id         = var.route53_zone_id
  name            = local.acm_validation[each.key].name
  type            = local.acm_validation[each.key].type
  records         = [local.acm_validation[each.key].value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = local.manage_dns ? [for r in aws_route53_record.acm_validation : r.fqdn] : null
}

resource "aws_route53_record" "api" {
  count = local.manage_dns ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.api_domain
  type    = "A"

  alias {
    name                   = aws_lb.api.dns_name
    zone_id                = aws_lb.api.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "channel" {
  count = local.manage_dns ? 1 : 0

  zone_id = var.route53_zone_id
  name    = "*.${var.api_domain}"
  type    = "A"

  alias {
    name                   = aws_lb.channel.dns_name
    zone_id                = aws_lb.channel.zone_id
    evaluate_target_health = true
  }
}
