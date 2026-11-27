# Klav Cloud hosted proxy: operations runbook

How to run Klav Cloud's hosted credential proxy on AWS Nitro Enclaves ([ADR 0051](../../docs/decisiones/0051-hosted-nitro-enclave-proxy.md)): the release-authority key, the manifests, the first deployment, the standby, upgrades, failover, revocation, total loss, and the hand test before going live.

> **This is not live yet.** The release-authority keys are pinned: `RELEASE_AUTHORITY_KEYS` in `klav-core` and `KLAV_ENCLAVE_RELEASE_KEYS` in `Dockerfile.enclave` hold the active key (`a8aa68a5…4abc45`) and the backup (`b25c2385…189e88`) (§2.1). **One thing still blocks going live** (ADR 0051 §18): the hand test on real Nitro hardware (§10). That covers bringing the loopback interface up, `/dev/nsm`, vsock, joining through the API load balancer, and how long a switch between zones takes.

## Contents
1. [What runs where](#1-what-runs-where)
2. [The release-authority key and the manifests](#2-the-release-authority-key-and-the-manifests)
3. [Infrastructure and the parent bundle](#3-infrastructure-and-the-parent-bundle)
4. [Genesis: the first deployment](#4-genesis-the-first-deployment)
5. [The standby: joining the second zone](#5-the-standby-joining-the-second-zone)
6. [Rolling upgrade](#6-rolling-upgrade)
7. [Failover when the zone in service fails](#7-failover-when-the-zone-in-service-fails)
8. [Revoking an image, and total loss](#8-revoking-an-image-and-total-loss)
9. [Monitoring and routine](#9-monitoring-and-routine)
10. [Hand test on AWS before going live](#10-hand-test-on-aws-before-going-live)

## 1. What runs where

```
                       ┌────────────── zone a (in service) ──────────────┐
 *.proxy.klav.dev ─▶ channel NLB (TCP 443) ─▶ :443  ┐                    │
 proxy.klav.dev   ─▶ API NLB (TLS 443)     ─▶ :8443 ├ klav-nitro-parent ─vsock─▶ enclave (join image, holds the seed, serves)
 NLB health       ─▶                          :8080 ┘   egress: CONNECT host:443 only, public addresses only
                       └─────────────────────────────────────────────────┘
                       ┌────────────── zone b (standby) ─────────────────┐
                       │ the same, attached to no load balancer: the     │
                       │ enclave joined from zone a (it holds the seed)  │
                       │ and serves nobody                               │
                       └─────────────────────────────────────────────────┘
```

- **The enclave image** (`deploy/nitro/Dockerfile.enclave`) comes in two variants per commit, because an EIF bakes its command line into PCR2:
  - **join**: `--bootstrap join --join https://proxy.klav.dev`. It reaches the enclave in service through its own parent's egress, as a `CONNECT proxy.klav.dev:443`. This is the only image `klav-enclave.service` starts.
  - **genesis**: `--bootstrap genesis`, which makes a new seed. An operator starts it by hand, only at the first deployment and after a total loss.
- **One zone in service, one standby.** The hand-off at `a4866c6f` is a snapshot (ADR 0051 §16). If two enclaves served at once, a forwarder's claim on one would be unknown to the other, and the sandbox would end as `theft`. So Terraform attaches at most one parent to the load balancers, and the other holds the seed as a standby. A joined enclave starts an account's proxy (and its heartbeat) only when a connection for that account arrives, so a standby attached to no load balancer doesn't fight the serving enclave over heartbeat epochs.
- **The standby's state is as old as its last join.** If it takes over, a sandbox claimed on the old enclave after that join gets `401`, and if it claims again, it ends as `theft`. Re-join the standby after every change and daily (§9) to keep that window short.
- **Ports:** 443 for channels, 8443 for the API and the hand-off (no `--peer`, so the hand-off is on the API), 8080 for health. vsock: enclave CID 16, ports 5000 (channel), 5001 (API) and 5002 (egress, on the parent).
- **Readiness is `GET /v1/manifest` answering 200.** The parent's `/healthz` answers 200 as soon as the enclave accepts a connection, which is *before* it has a seed. Until the seed arrives and a manifest is loaded, the API answers `503 klav_hosted_starting`. Every step below waits on `/v1/manifest`, never on load balancer health. On a parent, through SSM:
  ```sh
  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/manifest   # 200 = ready
  curl -s http://127.0.0.1:8443/v1/manifest | jq -r .manifest | jq '{seq, seed_epoch}'
  ```
- **The enclave's logs are invisible in production.** The only way to see them is `--attach-console` or `--debug-mode`, and both make an enclave report zero PCRs, which devices refuse (ADR 0051 §2.2). Judge an enclave by its API and by the parent's journal (`journalctl -u klav-nitro-parent`, which shows the egress `CONNECT`s and refusals). Never start a production enclave in debug mode.

## 2. The release-authority key and the manifests

### 2.1 Create the keys (once, on Omar's Mac)
ADR 0051 §11.5 calls for two Ed25519 keys: the **active** key, a Klav vault item on Omar's Mac, and an **offline backup**. Until `klav release sign-manifest` exists, signing goes through OpenSSL with the key served by `klav inject` (§2.3).

1. Create each key in memory and store it in the vault. The private key never touches the disk:
   ```sh
   brew install openssl jq     # OpenSSL 3; macOS's /usr/bin/openssl is LibreSSL
   export PATH="$(brew --prefix openssl)/bin:$PATH"
   klav item add note --title klav-release-authority-active --vault Personal --project General
   d=$(mktemp -d); mkfifo "$d/k.pem"
   openssl genpkey -algorithm ed25519 -out "$d/k.pem" &
   klav item attach klav-release-authority-active key "$d/k.pem" --name active.pem
   rm -rf "$d"
   ```
   If `klav item attach` refuses a named pipe, use a RAM disk instead (`diskutil erasevolume HFS+ klavram "$(hdiutil attach -nomount ram://16384 | tr -d '[:space:]')"`: 8 MiB, because APFS refuses a 1 MiB `ram://2048` disk, and `hdiutil` pads the device name with whitespace), write the key there, attach it, and eject the volume. Never write it to the internal disk.
2. Read each public key (64 hex characters) from the vault:
   ```sh
   d=$(mktemp -d)
   klav inject -r 'klav://Personal/General/klav-release-authority-active/key' --fifo -o "$d/k.pem" --ttl 2m &
   openssl pkey -in "$d/k.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 64
   rm -rf "$d"
   ```
3. **Backup key:** do the same with the title `klav-release-authority-backup`. Then move it out of the everyday vault: export its PEM once to two encrypted offline media (an encrypted USB drive in a safe, and a paper printout of the PEM in a separate place), and delete the item from the Mac's vault. The backup signs only if the active key is lost or stolen. It must not live on the same machine.
4. **Pin both public keys in one PR** (ADR 0051 §14), done for the current keys:
   - `crates/klav-core/src/nitro/manifest.rs`: `RELEASE_AUTHORITY_KEYS = &[active, backup]`;
   - `deploy/nitro/Dockerfile.enclave`: `ENV KLAV_ENCLAVE_RELEASE_KEYS="<active hex>,<backup hex>"`.

   Both are part of the image, and so of PCR0 and PCR2. Only images built from that commit onward can start. The pinned keys:
   - active: `a8aa68a51a5d6cee7b2c2789cea049ac1c6a2f80d98d1416ddc49fcf074abc45`
   - backup: `b25c2385c2179b8fd404e12b513ab512aa2048ec14b4b03bfb62d08c0e189e88`

**If the active key is lost or stolen:** sign a manifest with the backup that revokes nothing new, then release a version that pins a new active key and keeps the backup. A stolen key can list a rogue image, but an enclave hands the seed over only for a manifest already public in `deploy/nitro/manifests/` (ADR 0051 §4.2). Watch that folder's history: a commit there that you didn't make is an incident.

### 2.2 The manifest repository
The public log is this repository's `deploy/nitro/manifests/` on `main` (see its [README](manifests/README.md)). The enclaves fetch `<seq>.json` and `<seq>.json.sig` from `raw.githubusercontent.com` and require them byte-equal to the manifest in a hand-off. Rules:
- Publish a manifest by merging a PR that adds exactly `<seq>.json` and `<seq>.json.sig`. Never edit or re-save a published file.
- `seq` only grows. A manifest lasts at most 30 days, so re-issue one before then (§9).
- Merging there deploys nothing. These paths are outside `main`'s production watch paths, and enclaves only read the folder.

### 2.3 Drafting and signing a manifest
1. Run `eif.yml` for the release commit (on a `v*` tag it runs by itself):
   ```sh
   gh workflow run eif.yml -f sha=<40-hex> \
     -f parent_role_arn="$(terraform -chdir=deploy/nitro/terraform output -raw parent_role_arn)" \
     -f egress="$(terraform -chdir=deploy/nitro/terraform output -json egress_cidrs | jq -r 'join(",")')"
   ```
   It fails unless two independent builds give the same PCR0, PCR1 and PCR2. Its artifacts are `klav-nitro-measurements`, `klav-nitro-bundle` and `klav-nitro-manifest-draft` (`<seq>.json`, unsigned).
2. **Rebuild it yourself** before signing, so you aren't trusting the CI run alone: `deploy/nitro/build-eif.sh` on the same commit must print the same PCRs as `images.json`.
3. Review the draft: `seq`, `seed_epoch`, every image's status (the previous `current` became `draining`), `parent_roles`, `egress`, and an expiry 30 days out. To draft by hand instead, use `deploy/nitro/draft-manifest.sh --seq N --images images.json --previous deploy/nitro/manifests/<N-1>.json …`.
4. Sign it, with the key served once through a pipe:
   ```sh
   d=$(mktemp -d)
   klav inject -r 'klav://Personal/General/klav-release-authority-active/key' --fifo -o "$d/k.pem" --ttl 2m &
   deploy/nitro/sign-manifest.sh --manifest deploy/nitro/manifests/drafts/<seq>.json \
     --key "$d/k.pem" --release-key <active public key hex>
   rm -rf "$d"
   ```
5. Move `<seq>.json` and `<seq>.json.sig` into `deploy/nitro/manifests/`, open a PR and merge it. Then check the published copy: `deploy/nitro/verify-release.sh --seq <seq> --release-key <active> --release-key <backup> --no-rebuild`.

## 3. Infrastructure and the parent bundle

1. Apply the Terraform (see its [README](terraform/README.md)). With the default `zones`, zone `a` is in service and zone `b` is the standby. Create the DNS records from the outputs: `proxy.klav.dev` → the API NLB, `*.proxy.klav.dev` → the channel NLB, and the ACM validation record.
2. Download `klav-nitro-bundle` from the `eif.yml` run, check its `.sha256`, and copy it to both parents. The instances have no S3 access, so copy it through SSM, for example with a presigned URL from a bucket outside this stack and `curl` inside an SSM session.
3. On each parent, as root, through `aws ssm start-session --target <instance id>`:
   ```sh
   tar -xzf klav-nitro-bundle-<commit>.tar.gz
   klav-nitro-bundle-<commit>/parent/install.sh --bundle klav-nitro-bundle-<commit>
   ```
   This checks `SHA256SUMS`, installs `nitro-cli` 1.5.3 (the version the EIFs were built with), the allocator (1 vCPU, 2048 MiB), `klav-nitro-parent.service` and `klav-enclave.service`, and enables both. It does not start an enclave.

## 4. Genesis: the first deployment
Only for the very first enclave, or after a total loss (§8.2). **Never while any enclave holds the seed:** a second genesis splits the service into two seeds.

1. Publish manifest 1 (§2.3). It lists both images of the release (genesis and join), `seed_epoch: 0`, the `parent_roles` PCR3 of `parent_role_arn`, and the `egress` CIDRs.
2. On zone `a`, the zone in service:
   ```sh
   nitro-cli run-enclave --eif-path /opt/klav/eif/klav-enclave-genesis.eif \
     --cpu-count 1 --memory 2048 --enclave-cid 16 --enclave-name klav-proxy
   ```
3. Give it the published manifest. A genesis image has no `--manifest-seq` baked in, so it waits for `POST /v1/manifest`, and it accepts only a manifest whose signature verifies and which lists its own image:
   ```sh
   jq -n --rawfile m 1.json --arg s "$(tr -d '\n' < 1.json.sig)" '{manifest: $m, signature: $s}' \
     | curl -sf -X POST -H 'content-type: application/json' --data @- http://127.0.0.1:8443/v1/manifest
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/manifest    # 200
   ```
   Fetch `1.json` and `1.json.sig` from `raw.githubusercontent.com` (the published bytes), not from your laptop.
4. **The service key.** The enclave serves the Ed25519 public half of its service key on `GET /v1/status`: `null` until it holds a seed, then 64 lowercase hex characters. The enclave also logs it once, but its console isn't readable without debug mode (§1), so read it from the API. It is a public key, not a secret. On zone `a`, through SSM:
   ```sh
   key=$(curl -sf http://127.0.0.1:8443/v1/status | jq -r .service_key)
   printf '%s\n' "$key" | grep -Eqx '[0-9a-f]{64}' && echo "$key"   # nothing printed = no seed yet; don't go on
   ```
   Cross-check it through the API load balancer: `curl -sf https://proxy.klav.dev/v1/status | jq -r .service_key` must print the same string. Then, from a machine logged in to Railway, set it on `api.klav.dev` (the `klav-server` service). Railway redeploys the service when a variable changes:
   ```sh
   railway variables --service klav-server --set "KLAV_HOSTED_PROXY_SERVICE_KEY=<the 64 hex characters>"
   ```
   `klav-server` refuses to start with a value that isn't 64 hex characters, so check the deploy logs. Until the key is set, every enroll is refused with `403 klav_hosted_not_entitled`, and so is every enroll after a key mismatch. Each genesis makes a new seed and therefore a new key, while a join keeps the holder's key.
5. Turn the entitlement on for the beta accounts: `klav-server hosted-proxy enable <email>` (ADR 0051 §15).
6. `systemctl enable klav-enclave.service` is already done by the installer. **Don't start the unit on zone `a` while the genesis enclave runs.** The genesis enclave stays as the holder until its first replacement in a rolling upgrade (§6), and the unit takes over from then on.

## 5. The standby: joining the second zone
1. On zone `b`, the standby, which no load balancer reaches: `systemctl start klav-enclave.service`. The join image connects to `https://proxy.klav.dev` through its parent's egress, which reaches the one enclave in service. The two attest each other, and the holder seals the seed and every account's state to the joiner (ADR 0051 §4.2). The holder checks that:
   - the joiner's image is in the holder's manifest and not older than its own;
   - the joiner's PCR3 is in `parent_roles`;
   - the manifest is byte-equal to the published `<seq>.json`.
   It retries every 5 s for 5 minutes.
2. Ready when `curl … 127.0.0.1:8443/v1/manifest` answers 200 on zone `b`, with the holder's `seq`, and `curl -s http://127.0.0.1:8443/v1/status | jq -r .service_key` prints the same key as zone `a` (the same seed). If it never does, read `journalctl -u klav-nitro-parent` on `b`. A refused egress shows why (the address or the port), and a join that never connects shows as no `CONNECT proxy.klav.dev:443` at all. Then `systemctl restart klav-enclave.service`.
3. **Never attach a parent before its enclave has joined.** With the client address preserved, the joiner's own `CONNECT` to `proxy.klav.dev` could come back to itself.

## 6. Rolling upgrade
From release R1 (running on both zones) to R2. The hand-off only goes to an image that is not older, under a published manifest that lists both images.

1. Run `eif.yml` for R2, rebuild it yourself, and publish manifest N+1: R2's two images `current`, R1's two `draining` (§2.3).
2. Give N+1 to both running enclaves, since a holder judges a joiner against the manifest it holds. The API NLB reaches the zone in service, and SSM reaches the standby:
   ```sh
   body=$(jq -n --rawfile m N+1.json --arg s "$(tr -d '\n' < N+1.json.sig)" '{manifest: $m, signature: $s}')
   curl -sf -X POST -H 'content-type: application/json' --data "$body" https://proxy.klav.dev/v1/manifest
   # and on the standby, through SSM:
   curl -sf -X POST -H 'content-type: application/json' --data "$body" http://127.0.0.1:8443/v1/manifest
   ```
3. **Standby (`b`) to R2:** install R2's bundle (`install.sh`, no `--start`), then `systemctl restart klav-enclave.service`. The R2 enclave joins from `a` (R1). Wait for `/v1/manifest` 200 on `b`.
4. **Switch right away** (ADR 0051 §16: the hand-off goes right before the old enclave leaves the load balancer). Swap `in_service` (`a = false`, `b = true`) and run `terraform apply`. The apply registers `b` and deregisters `a`. `a` keeps its open connections for `deregistration_delay_seconds` (60 s), and new connections go to `b` once it passes two health checks (about 20 s). Whether connections fail in that gap is **not measured yet** (§10).
5. **The old zone (`a`) to R2:** first confirm `b` serves (`/v1/manifest` 200 through `https://proxy.klav.dev`). Install R2's bundle on `a`, then stop its enclave explicitly and start the unit:
   ```sh
   nitro-cli terminate-enclave --enclave-name klav-proxy   # needed after genesis: that enclave was started by hand, not by the unit
   systemctl restart klav-enclave.service
   ```
   It joins from `b` (R2) and becomes the standby.
6. Later, once no enclave runs R1, publish a manifest that drops R1 (or revokes it, §8.1).

Never stop the last enclave holding the current seed. Check the standby has joined before you touch the zone in service.

## 7. Failover when the zone in service fails
1. The signal: alarm `…-no-healthy-target` or `…-status-check-failed` for the zone in service, or `https://proxy.klav.dev/v1/manifest` answering anything but 200. **A rebooted or auto-recovered parent in service does not trip the health alarm:** its new enclave accepts connections at once (`/healthz` 200) while it has no seed (`503 klav_hosted_starting`), and its join image dials `proxy.klav.dev`, which routes back to itself, so it can never join while its zone is in service. It retries for about 5 minutes, then gives up. Check `/v1/manifest` after any event on the zone in service.
2. Check the standby on `b`: `/v1/manifest` 200.
3. Swap `in_service` and run `terraform apply`. Sandboxes claimed after the standby's last join must claim again, and some may end as `theft` (§1). Tell affected people to start their sandbox again.
4. Repair `a` (reboot it, or let AWS recover it), then **after the swap** start its join explicitly: `nitro-cli terminate-enclave --enclave-name klav-proxy; systemctl restart klav-enclave.service`. The join at boot has already given up, or failed against itself. Check `/v1/manifest` 200 on `a`, which is now the standby.
5. If both zones fail at once, that is a total loss (§8.2).

## 8. Revoking an image, and total loss

### 8.1 Revoking a buggy image
Devices refuse a `revoked` image in a later manifest. A joiner also refuses a seed from a holder whose image is revoked, so revocation follows the upgrade:
1. Build and publish the fix as R3 with R_bad `draining` (manifest N+1), and roll it out (§6).
2. Publish N+2 with R_bad `revoked`. POST it to both enclaves.
3. Tell affected people whether they must stop using the hosted proxy and rotate provider tokens (ADR 0036 §18). A bug in an approved image is not prevented, only stopped going forward (ADR 0051 §10).

**If the image may have leaked the seed** (a compromise, not just a bug), treat the seed as gone. Revoke R_bad at once in N+1, then follow §8.2 on purpose with a fixed image: a new seed means new account keys, and every person sets the hosted proxy up again.

### 8.2 Total loss (both enclaves gone, or the seed compromised)
What happens to people is in ADR 0051 §4.4: sandboxes fail with `klav_proxy_unreachable`, and `GET /v1/attest` answers `404 klav_hosted_not_enrolled` for every account until each person sets the proxy up again on a device.
1. Publish a manifest with **`seed_epoch` + 1**, so devices can tell "lost its keys" from "a broken endpoint". Keep the current images.
2. Genesis on the zone in service (§4, steps 2–3).
3. **New service key:** a new seed means a new service key. Read the new public key from `GET /v1/status` and set it in `KLAV_HOSTED_PROXY_SERVICE_KEY` on `api.klav.dev` (§4 step 4) before anyone re-enrolls.
4. Join the standby (§5).
5. People re-enroll from the layer-5 sheet. The enclave registers a **new** agent (new `agent_id`, so a new `a<agent_id>.proxy.klav.dev`), the device re-wraps every credential and re-signs the issuers, and revokes the old agent. A per-account reset (`generation + 1`, §3.2) is the same flow for one account.
6. Post a status note: what happened, and that no key left an enclave (or, after a compromise, which tokens to rotate).

## 9. Monitoring and routine
- **Alarms** (`terraform/alarms.tf`): no healthy target, an unhealthy target, failed status checks, and automatic recovery on a failed system check. Point `alarm_actions` at an SNS topic that pages.
- **A parent in service that reboots or recovers comes back without a seed and stays "healthy"** (§7, step 1): check `https://proxy.klav.dev/v1/manifest` after any event on it, and fail over.
- **The standby is not monitored by AWS.** Through SSM, after every change and once a day:
  ```sh
  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/manifest   # on the standby: 200
  nitro-cli describe-enclaves | jq '.[0] | {State, EnclaveCID, CPUCount, MemoryMiB, Flags}'   # Flags "NONE", never DEBUG_MODE
  ```
  Then re-join it, so its snapshot is fresh: `systemctl restart klav-enclave.service` on the standby, then wait for 200. For those seconds only the zone in service holds the seed.
- **Manifest expiry:** devices refuse a manifest past `expires_at_ms` (at most 30 days). Every three weeks, publish a new `seq` with the same images (`draft-manifest.sh --previous <last>.json --images <the running release's images.json>`, which keeps those images `current`), sign it, and POST it to both enclaves.
- **The manifests folder:** watch `deploy/nitro/manifests/` on `main` for commits you didn't make.
- **Logs:** the parent's journal (`journalctl -u klav-nitro-parent -u klav-enclave`). The enclave's own logs stay inside it (§1).

## 10. Hand test on AWS before going live
Each item needs evidence in the PR (commands and output; never a secret). What ran is in ADR 0051 §18 (2026-11-27).

- [ ] `eif.yml` on GitHub's `ubuntu-24.04-arm`: two runners agree on PCR0, PCR1 and PCR2 for both images (ADR 0051's layer 6 stop rule; done at `a86a4057` and `23f82370`). Then `verify-release.sh` on another machine agrees too (not recorded yet).
- [x] Real PCRs match: `nitro-cli describe-enclaves` on a parent shows the same PCR0/1/2 as `images.json`, and a real attestation document from `GET /v1/attest` verifies in `klav-core` against the published manifest.
- [ ] The enclave starts on real hardware: `lo` comes up (busybox `ip`), `/dev/nsm` opens, vsock 5000/5001/5002 work, and egress reaches `api.klav.dev` and `raw.githubusercontent.com`.
- [x] A real attestation document from Klav's enclave added to `docs/vectores/nitro-attestation.json` (ADR 0051's layer 6 deliverable): `klav-proxy-2026-11-27-us-east-2a`.
- [x] `klav proxy use klav` from a device enrolls, verifies the attestation and turns the hosted proxy on (needs layer 5, and the service key set on `api.klav.dev`, §4 step 4).
- [ ] A Boat sandbox calls `northflank` and Maple's MCP through the hosted proxy (`klav sandbox start`, then a wrapped credential works).
- [ ] The standby joins (§5), and `/v1/manifest` answers 200 on it.
- [ ] Losing a zone: stop the zone in service (`nitro-cli terminate-enclave`), fail over (§7), and a running sandbox goes on working, or claims again without `theft` if it started before the standby's last join. Record how long sandboxes were down.
- [ ] Rolling upgrade (§6) with a sandbox calling a provider in a loop: count failed calls during the switch. ADR 0051 asks for none. If some fail, record how many and how long.
- [ ] Forced total loss (§8.2): both enclaves stopped, genesis with `seed_epoch` + 1, the new service key set on the server, a device shows the set-up-again sheet, and re-wrapping restores a sandbox.
- [ ] Load: a 1-vCPU, 2-GiB enclave under the beta's expected load (ADR 0051 §13).
