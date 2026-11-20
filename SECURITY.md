# Security policy

Klav is a password manager. A security bug in it can expose real secrets, so thank you for reporting carefully and privately.

## Project status

Klav is in early development. **Don't use it for real secrets yet.** We still want every finding, and above all findings in:

- `crates/klav-core`, the only place where cryptography lives;
- the [crypto spec](docs/especificacion-cripto.md) and its test vectors in `docs/vectores/`;
- how agents get access: permissions, approvals, tasks and the audit log;
- the browser extension's filling and saving, and the iOS AutoFill extension.

## How to report a vulnerability

**Never open a public issue, discussion or pull request about a vulnerability.**

1. **Preferred:** GitHub private vulnerability reporting. Go to **Security → Report a vulnerability** in this repository. The report stays private between you and the maintainers. We fix it in a private fork, and the advisory is published with the fix.
2. **If you can't use GitHub:** email **security@klav.dev** with the subject "Klav security". Don't put details in the first email; ask for a private channel and we'll set one up.

Please include:

- the affected commit or version, and the component: core, server, CLI, `klavd`, extension, iOS, Mac or web;
- the steps to reproduce, or a proof of concept;
- the impact: which secret or which guarantee breaks, and for whom (another user, an agent, the server, another process on the device);
- whether you need credit, and under which name.

### Reports written with AI tools

Using AI tools to research is fine. Sending what they produce without checking it is not. We only accept reports that a person has reproduced, with a concrete proof of concept against Klav's code or a running instance. We close scanner output and unverified LLM write-ups without a detailed reply.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 72 hours |
| First assessment and severity | 7 days |
| Fix or mitigation plan | depends on severity; critical issues first, as fast as we can |
| Coordinated disclosure | when the fix is released, and no later than 90 days after the acknowledgement unless we agree otherwise |

We publish fixed vulnerabilities as GitHub Security Advisories, requesting a CVE when one applies. The advisory and the changelog credit you, unless you'd rather stay anonymous. There is no paid bug bounty yet.

## Scope

**In scope:**

- all the code in this repository;
- the formats defined in the [crypto spec](docs/especificacion-cripto.md);
- the hosted server at `api.klav.dev` and the site at `klav.dev`, under the testing rules below.

**Out of scope.** See the [threat model](docs/modelo-de-amenazas.md) for the reasoning.

- Malware running as root, or as the same user with full control of the device.
- Attacks that need the victim to give away both their master password and their Secret Key.
- Volume denial of service against any instance.
- Instances that other people host.
- Reports that only say a header, a TLS setting or a dependency version is "best practice", with no way to exploit it in Klav.

## Testing rules

- Use only accounts and vaults that you own. Prefer your own server (see [self-hosting](docs/self-hosting.md)) to `api.klav.dev`.
- No denial of service, spam, social engineering or phishing, and no physical attacks.
- Don't access, change or keep other people's data. If you reach any by accident, stop, delete it and tell us.
- Give us the time in the table above before you disclose anything.

## Safe harbor

If you research in good faith and follow this policy, we consider your research authorized. We won't take legal action against you or report you to the authorities for it. If someone else does, we'll make clear that you acted within this policy. This covers only what Klav's maintainers can decide; it doesn't bind third parties, such as hosting providers or other people's instances.

## Supported versions

Until Klav reaches 1.0, only the `main` branch and the latest published build of each app get security fixes.

## Audits

Klav hasn't had an external security audit yet. One is planned before 1.0, and its report will be published in this repository.
