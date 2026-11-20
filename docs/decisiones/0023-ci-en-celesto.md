# 0023 · CI on Celesto: a single job with the seven tasks in parallel

- Status: accepted; partly superseded by [0034](0034-ci-en-boat.md) (the *runner*, concurrency, the Rust installation and the cache)
- Date: 2026-11-04

## Context
GitHub stopped starting this private repository's CI jobs. Omar decided to move CI to **Celesto CI** (celesto.ai). They are self-hosted runners registered with a GitHub app, so they don't spend GitHub minutes. The per-minute platform charge GitHub announced for self-hosted runners is postponed.

Differences from `ubuntu-latest` that matter here:

- **Image.** Celesto uses its own Ubuntu 24.04 x64 image, not GitHub's. It carries Python, Node 24 with pnpm, Git, a C/C++ toolchain and Docker with Buildx and Compose. **It doesn't carry Rust.**
- **Billing and limits.** Celesto charges every VM minute, including setup and cleanup. Each job is a new VM with a 2 h cap.
- **Label.** `runs-on` carries a single label, `celesto-<tamaño>`, without `self-hosted`. Two Celesto labels, or one that doesn't exist, make setup fail.
- **Cache.** Celesto serves the Actions cache API (`actions/cache` and whatever uses it).
  - Its store is a different one, so the first run finds no cache.
  - PR branches can read `main`'s cache.
  - The limit per repository depends on the Celesto plan (5 GiB to 25 GiB).

The previous CI had seven jobs: `fmt`, `clippy`, `test`, `test (postgres)`, `docker`, `extension` and `cargo-deny`. Four of them each built the workspace on their own. On Celesto that would be seven VMs, each with its setup billed, four builds and seven simultaneous sandboxes.

## Decision
1. **A single job, `ci`, on `celesto-large`** (4 vCPU, 16 GB).
   - The size comes from the repository variable `CI_RUNS_ON`, so it can be changed without a PR.
   - Micro and Small aren't enough to build the workspace along with Chromium and the Docker image.
2. **The seven jobs become background tasks** of that job. The `.github/boated-ci/` engine runs them (`ci-task.ts`, the pattern of the *boated CI* skill).
   - They share the machine, the same `target/` and a single Rust cache.
   - Cargo queues its own builds with the `target/` lock.
3. **One check per task, with the same name as before**, because the orchestrator merges PRs by looking at those names.
   - Task names only allow `[a-z0-9-]`. The `CI_TASK_CHECK_NAMES` map translates them; for example, `test-postgres` becomes `test (postgres)`.
   - Each check carries the trimmed failure in `output.text`.
   - The `ci` job passes or fails according to the tasks' result.
4. **On a PR retry** (`gh run rerun <id> --failed`), tasks whose check already passed on the same merge commit are skipped. It is turned off with the variable `CI_TASK_SKIP_PASSED=false`.
5. **Tools installed in the job:**
   - **Rust:** rustup is installed with `curl`, pinned by version and SHA-256. The toolchain comes from `rust-toolchain.toml`, plus the `wasm32-unknown-unknown` target.
   - **`wasm-bindgen`:** at the version `Cargo.lock` sets.
   - **`cargo-deny`:** at the same version its action used. It now runs as a binary, not as a container action.
   - **Playwright:** it is installed with `--with-deps`, which needs `sudo`. If there is no `sudo`, the task fails with a clear message.
6. **Services.** Postgres stays as `services:`. The Docker image starts on a random `127.0.0.1` port instead of 8080.
7. **Security.**
   - Third-party actions stay pinned by SHA (T52 in the threat model).
   - The job has three permissions: `contents: read`, `checks: write` (to publish and re-read the task checks) and `actions: read` (to link the job's log).

## Consequences
- A PR starts one VM instead of seven and builds the workspace once instead of four times. The duration depends on the slowest task (`extension` or `test`), not on the sum of all of them.
- Until the Celesto app is installed on the repository with a plan that covers Large, the jobs stay queued.
- The Rust cache is saved only from `main`, even when a task fails. PR runs read it but don't write it, so as not to fill the per-repository limit. The first run on Celesto builds everything from scratch.
- **Logs.** Each task prints its output in its `<tarea>: result` step, with the trimmed failure at the top. The full logs are uploaded as an artifact (`ci-task-logs-<intento>`, 7 days).
- **Size.** At the end of the job, a table of metrics per task (the machine's CPU, *steal* and memory) helps to adjust the size. If `celesto-xl` halves the time, it costs the same per run and finishes sooner.
- **Going back to GitHub** requires reverting this change. Changing `runs-on` isn't enough, because GitHub's image already carries Rust and Celesto's doesn't.

## Note (2026-11-05): public repository, PRs from forks and CODEOWNERS
The context speaks of a "private repository". On 2026-11-05 the repository was still private, but it was going to be opened (roadmap, milestone C), and then anyone would be able to open a PR from a fork. This decision doesn't change; layer 12 of the security round (ADR 0030) adds, for that moment:

- **PRs from forks without a runner.** The `ci` job carries an `if:` and only runs on `push`es to `main` and on PRs whose branch lives in this repository, including those from `gh stack`, even if their base is another branch. A PR from a fork doesn't request a Celesto machine: it neither spends credit nor runs someone else's code on it. To test it, someone with permission pushes its branch to this repository.
  - GitHub treats a skipped job as passing, but the seven task checks aren't published: if `main`'s protection requires them by name, the fork's PR stays blocked until its branch is tested here.
- **`CODEOWNERS`** (`.github/CODEOWNERS`): `.github/`, `scripts/`, `deploy/`, the Docker files, `deny.toml`, `Cargo.lock`, `rust-toolchain.toml` and `crates/klav-core/` require Omar's review.
- **The `docker` task** also builds and starts the Railway image (`deploy/railway/Dockerfile`). It does so with a root-owned volume, the way Railway mounts it, and checks that the server runs with UID 10001, without *capabilities* and with `no_new_privs`, and that the *entrypoint* doesn't follow links or accept a `KLAV_DATA_DIR` outside `/data`. These are two *release* builds without a cache: the task takes longer and may become the slowest.

It is up to Omar, in GitHub's settings (it isn't in the repository): requiring approval for workflows from outside contributors (*Settings → Actions → General*) and turning on "Require review from Code Owners" in `main`'s protection, without which `CODEOWNERS` only suggests reviewers.

**Note (2026-11-13):** the second half no longer applies. [ADR 0040](0040-contribution-gating-and-discussions.md) (Q10, amended) leaves `main`'s *ruleset* without requiring CODEOWNERS review, with 0 approvals and no *bypass*: `CODEOWNERS` only requests the review. Approval of *workflows* from outside contributors still applies ([`docs/github-settings.md`](../github-settings.md), step 8).
