# 0034 · CI on Boat: the same `ci` job, on `boat-large`

- Status: accepted (partly supersedes [0023](0023-ci-en-celesto.md))
- Date: 2026-11-05

## Context
On 2026-11-05 Celesto stopped giving this repository machines (the plan's credit ran out). Since then every CI run gets stuck at the "Celesto runner setup" check and the `ci` job gets no machine. Omar decided to move CI to **Boat** (boat.dev). Omar already uses Boat, and the CI of another of Omar's repositories has run there since 2026-10-28.

The design of 0023 still stands: a single `ci` job, seven background tasks, one check per task with the usual name, and retries that skip what already passed. Only the *runner* provider changes.

What matters about Boat (docs.boat.dev/ci.md and /machines/tools.md, read on 2026-11-05, and what was seen in that other repository's CI):

- **Label.** `runs-on` carries a single label, without `self-hosted`. A label that doesn't exist is rejected. Sizes:

  | Label | vCPU | Memory |
  |---|---|---|
  | `boat-small` | 2 | 4 GB |
  | `boat` | 4 | 8 GB |
  | `boat-large` | 8 | 16 GB |
  | `boat-xlarge` | 16 | 32 GB |

- **Billing and limits.**
  - Each job is a new VM. It is billed per second, plus one **start** for each job that gets a *runner*.
  - A job skipped by its `if:` costs nothing. A job that already started and is then canceled has already paid its start.
  - A job's cap is 6 h (on Celesto it was 2 h).
- **Image.**
  - Ubuntu 24.04 x86_64, user `user`, passwordless `sudo`.
  - **It carries Rust** (stable 1.97.1) with rustup. Also Node 24 (and 22 in nvm), pnpm 10, Bun 1.3, Chrome, GCC, Clang, git 2.43 and gh.
  - Docker 29 with BuildKit and Compose. Docker may take a few seconds to answer after the machine is reported ready.
  - `LANG` and `LC_ALL` are `en_US.UTF-8`.
- **It behaves like a GitHub *runner*.** `services:` (Postgres on `localhost`), artifacts, secrets and `actions/cache` work.
  - The cache is the repository's own GitHub Actions cache: 10 GB, and an entry is deleted after 7 days unused. It isn't Celesto's store.
- The working directory is `$HOME/actions-runner/_work`. The `/_work/<repo>/<repo>/` paths that the failure extractor (`ci-task-extract.ts`) recognizes still work.

## Decision
1. **The `ci` job moves to `boat-large`** (8 vCPU, 16 GB).
   - The repository variable `CI_RUNS_ON` still overrides the size. Today it isn't set, so the workflow's default value applies.
   - `celesto-large` had 4 vCPU and 16 GB. `boat` (4 vCPU, 8 GB) falls short on memory to build the workspace along with Chromium and the Docker image. `boat-large` keeps the 16 GB and doubles the CPU.
2. **Concurrency: the run in progress is canceled only on PRs** (`cancel-in-progress: ${{ github.event_name == 'pull_request' }}`).
   - On a PR, a new push makes the previous run pointless. Its start is already paid, but its seconds are saved.
   - On `main`, a run that already started isn't canceled, because it would waste a paid start. GitHub keeps one run in progress and one pending per group. If another push arrives, it replaces the pending one before it asks for a machine, so a burst of merges doesn't cost extra starts.
3. **Rust.**
   - If the image already carries `rustup` in the `PATH`, or in `${CARGO_HOME:-~/.cargo}/bin`, it is used as is and `rustup self update` is never run.
   - If it doesn't, `rustup-init` is installed, pinned by version and SHA-256, as in 0023. That way the workflow still works on a *runner* without Rust.
   - In both cases, the toolchain and its components come from `rust-toolchain.toml`, plus the `wasm32-unknown-unknown` target. `~/.cargo/bin` (and, if it is a different one, the directory of the image's rustup) goes into `GITHUB_PATH`. The log shows which path was taken and the rustup version.
4. **Docker.** The `docker` task waits up to 60 s for `docker info` to answer before building anything, and if it doesn't answer it fails with a clear message. The Postgres service already needed Docker when the job started, so normally the wait ends at once. It goes inside the task, not in a separate step, so that a retry that runs `docker` also runs the wait.
5. **The job's *timeout* stays at 90 min**, even though Boat allows 6 h.
   - Since Boat bills every second, the *timeout* no longer serves to avoid hitting the provider's cap, but to bound what a hung run costs.
   - On Celesto (`celesto-large`, 4 vCPU), the 179 green runs between 2026-11-04 and 2026-11-05 took 8 min on average and 15 at most, counting the wait for a machine. Each task's `wait … 4800` (80 min) fits inside.
6. Everything else in 0023 stays the same: §2 to §4, the services (§6), security (§7, with actions pinned by SHA, T52) and the note of 2026-11-05 about PRs from forks and `CODEOWNERS`. A PR from a fork still gets no machine: it neither pays a start nor runs someone else's code on it.

## Consequences
- **One start per run.** Each run that gets a machine pays a start, even if it is canceled afterwards. A `gh stack` PR with several layers pays one per layer on each push that moves them.
- **Retries: only `gh run rerun <id> --failed`.** With a single job, `--failed` and a full retry start one VM each, and on a PR both skip the tasks that already passed on the same merge commit. The difference is on a green run: `--failed` has nothing to repeat and starts nothing, while "Re-run all jobs" pays a start to skip every task on a PR, or to build everything again on `main`. To run everything again, push a new commit.
- **`main` queues.** Two merges in a row run one after the other, and the second no longer cancels the first. A third push in the meantime replaces the second, which was still pending.
- **Cache.** The first run on Boat finds no cache and builds everything from scratch. Afterwards it reads the entry `main` saves. If `target/` outgrows the 10 GB, GitHub deletes old entries: the run is slower, but doesn't go red.
- **Size.** The per-task metrics table (CPU, *steal* and memory) says whether `boat-xlarge` is worth it (`gh variable set CI_RUNS_ON --body boat-xlarge`) or whether there is machine to spare. The Boat pages that were read don't say how much more each size costs per second: Boat's dashboard has to be checked after a few days before changing it.
- **As long as Boat's GitHub app doesn't cover this repository**, the `ci` job stays queued without a *runner*. Only Omar can add the repository in the app's settings.
- **Going back to Celesto** doesn't require reverting this change. `gh variable set CI_RUNS_ON --body celesto-large` is enough, as long as the Celesto app is still installed on the repository and has credit for Large: the Rust step installs `rustup-init` when the image carries no rustup, which is exactly what ran on Celesto.
  - What doesn't come back on its own is the concurrency: `main` keeps queuing. Celesto bills per minute, without starts, so there it would be better to go back to `cancel-in-progress: true` with a PR.
  - The first run on Celesto doesn't find a cache either, because its store is a different one.
  - To go back to Boat, `gh variable delete CI_RUNS_ON`.
- **Going back to GitHub's *runners*** (`CI_RUNS_ON=ubuntu-latest`) hasn't been tested. Their image carries rustup and the workflow uses nothing specific to Boat, but a run would be needed to confirm it.
