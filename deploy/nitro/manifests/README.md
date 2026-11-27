# Klav Enclave Transparency Manifests

Each signed manifest of Klav Cloud's hosted proxy lives here as `<seq>.json` with its `<seq>.json.sig` ([ADR 0051](../../../docs/decisiones/0051-hosted-nitro-enclave-proxy.md) §2.4). This folder on the default branch is the v1 transparency log:

- **A running enclave hands its seed only to an image listed in a manifest that is byte-identical to the one published here** (§4.2). A manifest the release authority signed but never published moves nothing.
- **Devices verify the signature** against the release-authority keys pinned in `klav-core` (`RELEASE_AUTHORITY_KEYS`). They refuse a `seq` lower than one they have seen, and any manifest past `expires_at_ms` (at most 30 days).
- **Anyone can check a manifest** by rebuilding its images: `deploy/nitro/verify-release.sh --seq N --release-key <hex>`.

Format:

- `<seq>.json` holds the exact bytes the release authority signed. Never reformat, re-indent or re-save a published file: the signature covers its SHA-256.
- `<seq>.json.sig` holds 128 lowercase hex characters (the Ed25519 signature over `tuple("klav/v1/sig/enclave-manifest", SHA-256(<seq>.json))`) and an optional final newline.

`drafts/` is where `draft-manifest.sh` writes unsigned drafts. It is git-ignored, and nothing there is ever served. How to draft, sign and publish is in the [runbook](../runbook.md) §2.

No manifest is published yet. The release-authority keys are pinned (ADR 0051 §14); the first manifest comes with the first deployment (runbook §4).
