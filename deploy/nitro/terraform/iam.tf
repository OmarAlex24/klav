# The parents' role: SSM Session Manager and Run Command for the operator,
# and nothing else (ADR 0051 §7.4). No KMS: the seed lives only in enclave
# memory (Q3 (a)), so there is no key for any AWS principal to unseal.
# No S3, no Secrets Manager, no CloudWatch Logs: the enclave's logs never
# leave it (runbook §9), and the parent's stay in its journal.
#
# Its ARN is what PCR3 measures (SHA-384 of 48 zero bytes and the ARN), the
# `parent_roles` of the manifest: a peer hands the seed only to an enclave
# whose parent has this exact role (ADR 0051 §4.2). Renaming the role, or
# recreating it in another account, changes PCR3: publish a manifest with
# the new value before any hand-off needs it.

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "parent" {
  name               = "${var.name}-parent"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
  description        = "Klav hosted proxy parent (ADR 0051): SSM only. Its ARN is PCR3 in the enclave manifest."
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.parent.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "parent" {
  name = "${var.name}-parent"
  role = aws_iam_role.parent.name
}

data "aws_partition" "current" {}
