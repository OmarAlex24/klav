output "parent_role_arn" {
  description = "The parents' IAM role ARN. Its PCR3 goes in the manifest's parent_roles: draft-manifest.sh --parent-role-arn."
  value       = aws_iam_role.parent.arn
}

output "parent_instance_ids" {
  description = "Parent instance per zone, for SSM (aws ssm start-session --target …)."
  value       = { for k, i in aws_instance.parent : k => i.id }
}

output "parent_public_ips" {
  description = "Each zone's Elastic IP (its fixed egress address)."
  value       = { for k, e in aws_eip.parent : k => e.public_ip }
}

output "egress_cidrs" {
  description = "The manifest's egress (draft-manifest.sh --egress), for ADR 0044's strict network profile."
  value       = sort([for e in aws_eip.parent : "${e.public_ip}/32"])
}

output "dns_records" {
  description = "Records to create by hand when route53_zone_id is empty (CNAMEs to the load balancers)."
  value = {
    api     = { name = var.api_domain, type = "CNAME", value = aws_lb.api.dns_name }
    channel = { name = "*.${var.api_domain}", type = "CNAME", value = aws_lb.channel.dns_name }
  }
}

output "acm_validation_records" {
  description = "The API certificate's DNS validation records (create them by hand when route53_zone_id is empty)."
  value       = local.acm_validation
}
