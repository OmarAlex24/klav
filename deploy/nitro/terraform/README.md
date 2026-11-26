# Klav Cloud hosted proxy: AWS infrastructure

Terraform for the AWS side of [ADR 0051](../../../docs/decisiones/0051-hosted-nitro-enclave-proxy.md) (§7.4, Q7): two Graviton `c7g.large` parents in two availability zones, each running one Nitro Enclave, behind two Network Load Balancers. How to deploy, upgrade and recover is in the [runbook](../runbook.md). This page covers what the Terraform creates.

## What it creates

| File | Resources |
|---|---|
| `network.tf` | A VPC with two public subnets in two zones, an internet gateway, and a default security group that allows nothing. With `create_vpc = false` it uses your VPC and subnets instead. |
| `instances.tf` | Two `c7g.large` parents on Amazon Linux 2023 arm64 with `enclave_options { enabled = true }`, IMDSv2 only (hop limit 1), an encrypted gp3 root volume, detailed monitoring, termination protection, and one Elastic IP each. The Elastic IPs are the fixed egress addresses listed in the manifest. `user_data` installs only `nitro-cli` and the allocator, and holds no secret. It can run before the Elastic IP attaches, in which case its `dnf install` fails; `install.sh` installs the same, so don't rely on first boot. |
| `iam.tf` | The parents' role, with **only** `AmazonSSMManagedInstanceCore`. No KMS (the seed lives only in enclave memory, Q3 (a)), no S3, no Secrets Manager. The role's ARN is what PCR3 measures, the manifest's `parent_roles`. |
| `security.tf` | Ingress on 443 (channels), 8443 (API and hand-off) and 8080 (health checks, from the VPC only). Egress on 443 only. **No port 22**: use SSM Session Manager. |
| `nlb.tf` | The **channel NLB**: TCP 443 passthrough to the parents' 443, client IP preserved. TLS ends inside the enclave, which routes by SNI (`a<agent_id>.proxy.klav.dev`, §3.4). The **API NLB**: TLS 443 with an ACM certificate, forwarding to the parents' 8443 with the client IP preserved. Both use cross-zone load balancing and health-check the parent's `GET /healthz` on 8080. |
| `dns.tf` | The API's ACM certificate. When `route53_zone_id` is set, also its validation record and the `proxy.klav.dev` and `*.proxy.klav.dev` aliases. |
| `alarms.tf` | No healthy target and unhealthy target for each target group, a failed EC2 status check for each parent, and automatic instance recovery on a failed system check. |

**One zone in service, one standby.** `var.zones` attaches at most one parent to the load balancers. A validation refuses two. The other parent runs an enclave that joined (it holds the seed) but serves nobody. At `a4866c6f` the hand-off is a snapshot, so two enclaves serving at once end sandboxes as theft (ADR 0051 §16). Failing over and upgrading move `in_service` from one zone to the other (runbook §6, §7). When the roadmap's continuous replication exists, both can serve.

**Never in this stack:** a KMS key, a secret, an SSH key pair, a port 22 rule, or anything that could unseal the seed. The state holds no secret. It does name every resource, so keep it in a private, versioned S3 bucket.

## Use

```sh
cd deploy/nitro/terraform
cp terraform.tfvars.example terraform.tfvars    # git-ignored; adjust
terraform init \
  -backend-config="bucket=<state bucket>" \
  -backend-config="key=klav/hosted-proxy.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="use_lockfile=true"
terraform plan -out plan.tfplan
terraform apply plan.tfplan
```

`klav.dev`'s DNS lives outside AWS, so leave `route53_zone_id` empty. Then, while `apply` waits on the certificate, create the records in the outputs `acm_validation_records` (the ACM validation CNAME) and `dns_records` (`proxy.klav.dev` and `*.proxy.klav.dev` as CNAMEs to the two load balancers).

Outputs used later:

| Output | Used by |
|---|---|
| `parent_role_arn` | `draft-manifest.sh --parent-role-arn` (PCR3 in `parent_roles`) |
| `egress_cidrs` | `draft-manifest.sh --egress` (the manifest's `egress`) |
| `parent_instance_ids` | `aws ssm start-session --target …` |

## Checks

```sh
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
terraform test       # plans against a mocked AWS provider: no account needed
```

`tests/plan.tftest.hcl` checks the defaults (two `c7g.large` with enclaves on, IMDSv2, encrypted volumes, two zones, one zone in service, client IPs preserved, ports 443/8443/8080 in and 443 out, an SSM-only role), failover to zone `b`, and that two zones in service or a third zone are refused.

## Cost

Two `c7g.large` on demand cost about $106 a month in `us-east-1`, or about $70 with a one-year Savings Plan (ADR 0051 §7.4, prices from third-party aggregators). Add two NLBs (an hourly charge plus capacity units), two public IPv4 addresses and data transfer out.
