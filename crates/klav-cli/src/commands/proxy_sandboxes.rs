//! `klav proxy sandboxes [revoke]` (ADR 0036 E2.1, E2.3, E6.2): the
//! person's list of the sandboxes of the account's proxy, from the
//! verified log and the proxy's signed heartbeat, and their revocation,
//! signed with the account's identity and without Touch ID, because it
//! only takes access away (risk 64). Labels and names are the issuer's and
//! the server's words: shown on one line, without control or hidden
//! characters, also in the JSON.

use std::time::{Duration, Instant};

use klav_client::sandbox_revoke::RevokeOutcome;
use klav_client::sandboxes::{
    EndReason, NoSigns, ProxyView, SandboxList, SandboxRow, SandboxStatus, SecurityFlag,
};
use klav_core::ids::{AgentId, SandboxId};
use klav_core::model::preferences::ProxyMode;
use klav_daemon::protocol::{ErrorCode, Request};
use klav_proto::sandbox::{RevokeTarget, SCOPE_ALL};
use serde::Serialize;

use crate::backend::{Backend, call};
use crate::cli::{ProxySandboxRevokeArgs, ProxySandboxesArgs, ProxySandboxesCommand};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, EXIT_SECURITY, usage};
use crate::output;

/// How long `--wait` waits for the proxy to log the ends. The proxy reads
/// the person's revocations every 30 s (ADR 0036 E3.3), so this covers a
/// few missed reads.
const WAIT_LIMIT: Duration = Duration::from_secs(120);

/// Between two reads of the list while waiting. Each read verifies the log.
const WAIT_EVERY: Duration = Duration::from_secs(10);

/// The shortest start of an ID that `revoke` takes: what the list shows.
const SHORT_ID: usize = 8;

pub(crate) async fn sandboxes_cmd(ctx: &mut Ctx, args: ProxySandboxesArgs) -> CliResult<()> {
    let json = match &args.command {
        Some(ProxySandboxesCommand::Revoke(r)) => r.json.json,
        None => args.json.json,
    };
    let result = match args.command {
        None => list_cmd(ctx, args.ended, args.json.json).await,
        Some(ProxySandboxesCommand::Revoke(r)) => revoke_cmd(ctx, r).await,
    };
    if json && let Err(e) = &result {
        super::sandbox::print_json_failure(e);
    }
    result
}

/// The verified list, of every proxy (`klav-client` keeps them all). A
/// security problem is an error (exit 3): for `--wait` with a setting that
/// is not flagged, and `klav proxy status`.
async fn the_list(ctx: &mut Ctx) -> CliResult<SandboxList> {
    match ctx.backend().await? {
        Backend::Direct(u) => Ok(u.sandbox_list().await?),
        Backend::Daemon(d) => call(d, Request::SandboxList).await.map_err(older_klavd),
    }
}

/// [`the_list`], except that preferences an agent wrote give the rows with
/// `security`, which [`list_cmd`] shows and exits 3 for. A klavd older than
/// the flag answers `bad_request`: then the plain list, which fails closed.
async fn the_flagged_list(ctx: &mut Ctx) -> CliResult<SandboxList> {
    flagged_list(ctx).await.map_err(|(e, _)| e)
}

/// [`the_flagged_list`], and with its error whether it came from a klavd
/// older than the flag (the plain list's refusal), which cannot give the
/// rows `revoke` needs while the setting is flagged.
async fn flagged_list(ctx: &mut Ctx) -> Result<SandboxList, (CliError, bool)> {
    match ctx.backend().await.map_err(|e| (e, false))? {
        Backend::Direct(u) => u
            .sandbox_list_flagged()
            .await
            .map_err(|e| (e.into(), false)),
        Backend::Daemon(d) => match call(d, Request::SandboxListFlagged).await {
            Err(CliError::Daemon(body)) if body.code == ErrorCode::BadRequest => {
                call(d, Request::SandboxList)
                    .await
                    .map_err(|e| (older_klavd(e), true))
            }
            other => other.map_err(|e| (e, false)),
        },
    }
}

/// What an older klavd leaves when the setting is flagged: no form of
/// `revoke` can name a proxy through it.
const OLDER_KLAVD_FLAGGED: &str = "the klavd running is older than revoking by the verified log's row while the account's proxy setting is flagged, so nothing was revoked: update klavd to this klav's version and restart it (`klav lock --stop`, then `klav unlock`), or set the proxy again with `klav proxy use own <agent>`";

/// A klavd from before these commands answers them with a generic
/// «malformed request»: say what to do instead.
fn older_klavd(e: CliError) -> CliError {
    match &e {
        CliError::Daemon(body) if body.code == ErrorCode::BadRequest => CliError::Other(
            "The klavd running is older than `klav proxy sandboxes`. Update klavd to this klav's version and restart it (`klav lock --stop`, then `klav unlock`), then try again.".into(),
        ),
        _ => e,
    }
}

/// The account's proxy's rows (E6.2), each text shown on one clean line.
fn of_account_proxy(list: SandboxList) -> SandboxList {
    let mut list = list.of_account_proxy();
    for r in &mut list.sandboxes {
        r.label = shown(&r.label);
        r.issuer_name = r.issuer_name.as_deref().map(shown);
        for p in &mut r.profiles {
            *p = shown(p);
        }
    }
    if let Some(p) = &mut list.proxy {
        p.name = p.name.as_deref().map(shown);
    }
    for w in &mut list.warnings {
        *w = shown(w);
    }
    list
}

/// The list. With a security problem the rows are still shown (every
/// proxy's, since no proxy is trusted), the problem is said as a security
/// warning, and the exit is 3: under `--json`, the one document holds it
/// in `security`.
async fn list_cmd(ctx: &mut Ctx, ended: bool, json: bool) -> CliResult<()> {
    let list = listed(of_account_proxy(the_flagged_list(ctx).await?), ended);
    if json {
        output::json(&ListJson::of(&list))?;
    } else {
        print_list(&list, ended, crate::time::now_ms());
    }
    match list.security {
        Some(_) => Err(CliError::Exit(EXIT_SECURITY)),
        None => Ok(()),
    }
}

/// The rows the list shows: every one with `--ended`; without it, those
/// not ended and whose proxy was not revoked (neither can change any
/// more), and those the theft signal ended, which a plain list never hides
/// (ADR 0036 E2.1, E6.2).
fn listed(mut list: SandboxList, ended: bool) -> SandboxList {
    if !ended {
        list.sandboxes.retain(|r| {
            !matches!(r.status, SandboxStatus::Ended | SandboxStatus::ProxyRevoked) || r.is_theft()
        });
    }
    list
}

/// `--json`: the list, and the IDs of its rows the theft signal ended.
/// `theft_signals` is always there, empty without one, so a script tells
/// «none» from a klav that does not say.
#[derive(Serialize)]
struct ListJson<'a> {
    #[serde(flatten)]
    list: &'a SandboxList,
    theft_signals: Vec<SandboxId>,
}

impl<'a> ListJson<'a> {
    fn of(list: &'a SandboxList) -> Self {
        Self {
            list,
            theft_signals: list.thefts().iter().map(|r| r.sandbox_id).collect(),
        }
    }
}

/// A line above the list's table: on standard output, or a warning on
/// standard error.
#[derive(Debug, PartialEq, Eq)]
enum Header {
    Out(String),
    Warn(String),
}

/// What the list prints above its table, in order: the proxy, the list's
/// warnings, and one security warning per theft signal, in the order the
/// sandboxes were issued. A theft line stays for as long as the log holds
/// that sandbox: the CLI has no «Got it» (ADR 0036 E2.1).
fn header_lines(list: &SandboxList) -> Vec<Header> {
    let proxy = match (&list.security, &list.proxy) {
        (Some(flag), _) => format!(
            "Proxy: security warning: {}. Below, the sandboxes of every proxy in the log.",
            flag.message()
        ),
        (None, Some(p)) => format!("Proxy: {}", proxy_line(p)),
        (None, None) => "Proxy: none (`klav proxy use own <agent>`). Below, the sandboxes of every proxy in the log.".to_owned(),
    };
    let mut lines = vec![Header::Out(proxy)];
    lines.extend(list.warnings.iter().cloned().map(Header::Warn));
    lines.extend(
        list.thefts()
            .into_iter()
            .map(|r| Header::Out(theft_line(r))),
    );
    lines
}

fn print_list(list: &SandboxList, ended: bool, now: i64) {
    for header in header_lines(list) {
        match header {
            Header::Out(text) => output::line(&text),
            Header::Warn(text) => output::warn(&text),
        }
    }
    output::line("");
    if list.sandboxes.is_empty() {
        output::line(if ended {
            "No sandboxes."
        } else {
            "No sandboxes to show without `--ended`, which also shows those that ended and those whose proxy was revoked."
        });
    } else {
        let rows: Vec<Vec<String>> = list.sandboxes.iter().map(|r| row(r, now)).collect();
        output::table(
            &[
                "ID",
                "LABEL (per the issuer)",
                "PROFILES",
                "ISSUER",
                "EXPIRES",
                "LAST SEEN",
                "STATE",
            ],
            &rows,
        );
    }
    output::line("");
    output::line(&format!("Verified up to event #{}.", list.verified_events));
}

/// `"klav-proxy" (77e0…): heartbeat 2 min ago`, and why it gives no signs.
fn proxy_line(p: &ProxyView) -> String {
    let who = match &p.name {
        Some(name) => format!("{} ({})", quoted(name), abbreviated(&p.agent_id)),
        None => p.agent_id.to_string(),
    };
    let beat = match (p.heartbeat_age_ms, p.no_signs) {
        (Some(age), _) if p.quiet => format!("heartbeat {}: no signs", ago(age)),
        (Some(age), _) => format!("heartbeat {}", ago(age)),
        // Not a quiet proxy: the server may be rolling it back.
        (None, Some(NoSigns::Rollback)) => format!(
            "security warning: {}; its heartbeat is not shown",
            no_signs_words(NoSigns::Rollback)
        ),
        (None, Some(why)) => format!("no signs ({})", no_signs_words(why)),
        (None, None) => "no signs".to_owned(),
    };
    if p.paused {
        format!("{who}: paused, {beat}")
    } else {
        format!("{who}: {beat}")
    }
}

fn no_signs_words(why: NoSigns) -> &'static str {
    match why {
        NoSigns::NoHeartbeat => "no heartbeat yet",
        NoSigns::NoEpoch => "the log has no store epoch of it",
        NoSigns::OtherEpoch => "its heartbeat is from another store epoch",
        NoSigns::Ahead => "its heartbeat is signed ahead of this device's clock",
        NoSigns::Version => "a heartbeat version this klav does not know: update klav",
        NoSigns::Rollback => {
            "the server sent an older heartbeat than this device has seen, as a server rolling it back would"
        }
        NoSigns::Unknown => "a reason this klav does not know: update klav",
    }
}

/// A theft signal, as a security warning that names the sandbox, its
/// label and issuer, and what to do: the words ADR 0036 E2.1 gives the
/// apps.
fn theft_line(r: &SandboxRow) -> String {
    let id: String = r.sandbox_id.to_string().chars().take(SHORT_ID).collect();
    let when = r.ended_at.map_or_else(String::new, |at| {
        format!(" at {} UTC", crate::time::format_utc_minutes(at))
    });
    format!(
        "Sandbox {id}: security warning: theft signal{when}. Someone claimed {} (per the issuer; issuer {}) a second time, and the proxy ended it. If it was neither you nor the issuer, someone copied its environment. `klav agent pause {}` also stops that issuer's other sandboxes.",
        quoted(&r.label),
        issuer(r),
        r.issuer_id
    )
}

/// `t3-code (a41c…)`, or the issuer's ID when the server no longer lists it.
fn issuer(r: &SandboxRow) -> String {
    match &r.issuer_name {
        Some(name) => format!("{name} ({})", abbreviated(&r.issuer_id)),
        None => r.issuer_id.to_string(),
    }
}

fn row(r: &SandboxRow, now: i64) -> Vec<String> {
    let live = matches!(
        r.status,
        SandboxStatus::Waiting | SandboxStatus::Active | SandboxStatus::Unknown
    );
    vec![
        r.sandbox_id.to_string().chars().take(SHORT_ID).collect(),
        quoted(&r.label),
        r.profiles.join(","),
        issuer(r),
        if live {
            super::sandbox::expires_in(r.expires_at)
        } else {
            "-".into()
        },
        r.last_seen_at
            .map_or_else(|| "-".into(), |at| ago(now - at)),
        state(r),
    ]
}

fn state(r: &SandboxRow) -> String {
    match r.status {
        SandboxStatus::Waiting => "waiting for claim".into(),
        SandboxStatus::Active if r.connected == Some(false) => "active, not connected".into(),
        SandboxStatus::Active => "active".into(),
        SandboxStatus::Revoking => match r.revoked_by_person_at {
            Some(at) => format!("revoking (revoked {} UTC)", minutes(at)),
            None => "revoking".into(),
        },
        SandboxStatus::Expired => "expired, its end not logged yet".into(),
        // Never «ended»: nothing proves it stopped (ADR 0036 risk 62).
        SandboxStatus::ProxyRevoked => match r.proxy_revoked_at {
            Some(at) => format!(
                "proxy revoked: its end can no longer be logged (proxy revoked {} UTC)",
                minutes(at)
            ),
            None => "proxy revoked: its end can no longer be logged".into(),
        },
        SandboxStatus::Ended => {
            let why = r.end_reason.map_or("ended", end_words);
            match r.ended_at {
                Some(at) => format!("{why} ({} UTC)", minutes(at)),
                None => why.into(),
            }
        }
        // A newer klavd's: never shown as ended.
        SandboxStatus::Unknown => "unknown state: update klav".into(),
    }
}

fn end_words(end: EndReason) -> &'static str {
    match end {
        EndReason::Stop => "stopped by the issuer",
        EndReason::Ttl => "expired",
        EndReason::Inactivity => "ended for inactivity",
        EndReason::Theft => "theft signal",
        EndReason::Released => "released by its forwarder",
        EndReason::IssuerRemoved => "issuer removed",
        EndReason::Person => "revoked by you",
        EndReason::PersonLocal => "revoked through the proxy's socket",
        EndReason::Unknown => "ended (a reason this klav does not know)",
    }
}

/// `HH:MM` of `ms`, UTC.
fn minutes(ms: i64) -> String {
    let full = crate::time::format_utc_minutes(ms);
    full.split_once(' ')
        .map_or(full.clone(), |(_, hm)| hm.to_owned())
}

/// `2 min ago`, `3h ago`, `2 days ago`; a time ahead of this clock is
/// `just now`.
fn ago(ms: i64) -> String {
    let min = ms.max(0) / 60_000;
    match min {
        0 => "just now".into(),
        1..=59 => format!("{min} min ago"),
        60..=2879 => format!("{}h ago", min / 60),
        _ => format!("{} days ago", min / 1440),
    }
}

/// The first 4 characters of an ID, as E6.2 shows an issuer: `a41c…`.
fn abbreviated(id: &AgentId) -> String {
    let s: String = id.to_string().chars().take(4).collect();
    format!("{s}…")
}

/// A name from outside, as `klav agent approve` prints it: escaped.
fn quoted(text: &str) -> String {
    format!("{text:?}")
}

/// `text` without control, format or separator characters.
fn shown(text: &str) -> String {
    text.chars()
        .filter(|c| !klav_core::text::is_hidden(*c))
        .collect()
}

/// `klav proxy status`'s lines (E6.2): [`status_lines`]. It verifies the
/// log: a security failure (tampering, a rollback of the synced data, a
/// heartbeat the proxy did not sign) is `status`'s error, exit 3, after
/// everything else is printed; any other failure is a warning.
pub(crate) async fn status_line(ctx: &mut Ctx) -> CliResult<()> {
    match the_list(ctx).await {
        Ok(list) => {
            for line in status_lines(&of_account_proxy(list)) {
                output::line(&line);
            }
            Ok(())
        }
        Err(e) if e.exit_code() == EXIT_SECURITY => Err(e),
        Err(e) => {
            output::warn(&format!(
                "Sandboxes: not shown: {}",
                shown(&e.message().unwrap_or_default())
            ));
            Ok(())
        }
    }
}

/// What `klav proxy status` says of the sandboxes: the proxy's security
/// warning, the same line `klav proxy sandboxes` prints, when the server
/// sent an older heartbeat than this device has seen (a warning, not exit
/// 3: ADR 0036 E9, 2026-11-16); each theft signal, the same line too, and
/// also a warning; then the counts. The list's other warnings,
/// such as an agent's event after its revocation, are for
/// `klav proxy sandboxes` and `klav log verify`.
fn status_lines(list: &SandboxList) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(p) = list
        .proxy
        .as_ref()
        .filter(|p| p.heartbeat_age_ms.is_none() && p.no_signs == Some(NoSigns::Rollback))
    {
        lines.push(format!("Proxy: {}", proxy_line(p)));
    }
    lines.extend(list.thefts().into_iter().map(theft_line));
    lines.push(counts_line(list));
    lines
}

/// `Sandboxes: 1 active, 2 waiting for claim`, and those of a state
/// this klav does not know, never left out.
fn counts_line(list: &SandboxList) -> String {
    let count = |s: SandboxStatus| list.sandboxes.iter().filter(|r| r.status == s).count();
    let unknown = match count(SandboxStatus::Unknown) {
        0 => String::new(),
        n => format!(", {n} of a state this klav does not know (update klav)"),
    };
    format!(
        "Sandboxes: {} active, {} waiting for claim{unknown} (`klav proxy sandboxes`)",
        count(SandboxStatus::Active),
        count(SandboxStatus::Waiting)
    )
}

/// What a revocation did, as `--json` prints it.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum RevokeView {
    Revoked {
        /// A sandbox ID, or `all`.
        scope: String,
        /// When it was signed (Unix ms).
        at: i64,
        /// The sandboxes it covers.
        sandbox_ids: Vec<SandboxId>,
        /// With `--wait`: those whose end the proxy has not logged yet
        /// (empty once it logged them all).
        #[serde(skip_serializing_if = "Option::is_none")]
        not_ended: Option<Vec<SandboxId>>,
    },
    NotApplied {
        scope: String,
        /// When the later revocation of the same scope was signed.
        later_at: i64,
    },
}

async fn revoke_cmd(ctx: &mut Ctx, args: ProxySandboxRevokeArgs) -> CliResult<()> {
    let target = target(ctx, &args).await?;
    let flag = target.flag.clone();
    match (revoke_at(ctx, &args, target).await, flag) {
        (Err(e), Some(flag)) => Err(under_flag(&flag, e)),
        (result, _) => result,
    }
}

/// While the setting is flagged, every failure exits 3 and says the flag:
/// the security problem is the worse one. One that already exits 3 stays.
fn under_flag(flag: &SecurityFlag, e: CliError) -> CliError {
    if e.exit_code() == EXIT_SECURITY {
        return e;
    }
    CliError::Coded {
        code: EXIT_SECURITY,
        error: None,
        message: shown(&flag.message()),
        next: Some(shown(&e.message().unwrap_or_else(|| {
            format!("the command failed (exit {})", e.exit_code())
        }))),
    }
}

/// The revocation of `target`, said, and with `--wait` its end.
async fn revoke_at(ctx: &mut Ctx, args: &ProxySandboxRevokeArgs, target: Target) -> CliResult<()> {
    let Target {
        proxy,
        target,
        flag,
        proxy_revoked,
    } = target;
    let outcome: RevokeOutcome = match ctx.backend().await? {
        Backend::Direct(u) => u.revoke_sandboxes_outcome(proxy, target).await?,
        Backend::Daemon(d) => {
            let scope = match target {
                RevokeTarget::One(id) => id.to_string(),
                RevokeTarget::All => SCOPE_ALL.to_owned(),
            };
            call(d, Request::SandboxRevoke { proxy, scope })
                .await
                .map_err(older_klavd)?
        }
    };
    let (scope, at, ids) = match outcome {
        RevokeOutcome::Revoked { revocation } => {
            (revocation.scope, revocation.at, revocation.sandbox_ids)
        }
        RevokeOutcome::NotApplied {
            scope, later_at, ..
        } => {
            not_applied(scope, later_at, args.wait, args.json.json, proxy_revoked)?;
            return still_flagged(flag.as_ref(), proxy);
        }
    };
    // What was revoked is said before any wait: a wait cut short, or a log
    // that fails to verify while waiting, never hides it.
    if args.json.json {
        output::json_line(&RevokeView::Revoked {
            scope: scope.clone(),
            at,
            sandbox_ids: ids.clone(),
            not_ended: None,
        })?;
    } else {
        output::line(&revoked_words(&scope, &ids, at, proxy_revoked));
    }
    if !args.wait {
        return still_flagged(flag.as_ref(), proxy);
    }
    if !args.json.json {
        output::info("Waiting for the proxy to log their end (at most 2 minutes)…");
    }
    let waiting = Waiting {
        ids: match target {
            RevokeTarget::One(id) => vec![id],
            RevokeTarget::All => ids.clone(),
        },
        all_at: matches!(target, RevokeTarget::All).then_some((proxy, at)),
    };
    let WaitEnd {
        open,
        proxy_revoked,
    } = wait_for_ends(ctx, &waiting, flag.is_some()).await?;
    let not_ended = Some(open);
    if args.json.json {
        output::json_line(&RevokeView::Revoked {
            scope,
            at,
            sandbox_ids: ids,
            not_ended: not_ended.clone(),
        })?;
    }
    match not_ended {
        Some(open) if !open.is_empty() => {
            if !args.json.json {
                let waited: Vec<SandboxId> = open
                    .iter()
                    .filter(|id| !proxy_revoked.contains(id))
                    .copied()
                    .collect();
                if !waited.is_empty() {
                    output::warn(&format!(
                        "The proxy has not logged the end of {} after 2 minutes. The server says it denies {} access, but only the end the proxy signs in the verified log proves it; `klav proxy sandboxes` shows it when it comes.",
                        list_ids(&waited),
                        if waited.len() == 1 { "it" } else { "them" }
                    ));
                }
                for id in &proxy_revoked {
                    output::warn(&proxy_revoked_words(*id));
                }
            }
            Err(not_ended_exit(flag.as_ref(), proxy))
        }
        _ => {
            if !args.json.json {
                output::line("The proxy logged their end.");
            }
            still_flagged(flag.as_ref(), proxy)
        }
    }
}

/// After a revocation made while the account's proxy setting is flagged
/// (by a verified row's proxy, [`target`]): the revocation is done and
/// said, and the problem still stands, so the command still exits 3 with
/// it, as the list does. It names the proxy, to compare with the row.
fn still_flagged(flag: Option<&SecurityFlag>, proxy: AgentId) -> CliResult<()> {
    match flag {
        None => Ok(()),
        Some(flag) => Err(CliError::Coded {
            code: EXIT_SECURITY,
            error: None,
            message: shown(&flag.message()),
            next: Some(format!(
                "the revocation above went to proxy {proxy}, the one the verified log names for that sandbox (its row's `proxy_id` in `klav proxy sandboxes --ended --json`), never to a proxy the setting names"
            )),
        }),
    }
}

/// A revocation refused while the setting is flagged: exit 3, the flag,
/// and why nothing was revoked.
fn flagged_refusal(flag: &SecurityFlag, why: &str) -> CliError {
    CliError::Coded {
        code: EXIT_SECURITY,
        error: None,
        message: shown(&flag.message()),
        next: Some(format!("{why}: nothing was revoked")),
    }
}

/// The revocation's line. With `proxy_revoked` (its verified row says so),
/// it says no end can come; otherwise, without a row read, it says what
/// proves an end, and that a revoked proxy gives none.
fn revoked_words(scope: &str, ids: &[SandboxId], at: i64, proxy_revoked: bool) -> String {
    let when = minutes(at);
    if scope == SCOPE_ALL {
        let covers = if ids.is_empty() {
            "it covers no live sandbox".to_owned()
        } else {
            format!("it covers {}", list_ids(ids))
        };
        format!(
            "Revoked every sandbox of the proxy issued so far, at {when} UTC: the revocation is signed, and the server says it stored it and {covers}. The server says it denies them access from now on; what proves each one stopped is its end, which the proxy signs in the verified log at its next read (every 30 s) and `klav proxy sandboxes` shows, unless the account revoked that proxy: then no end can come, and the list shows them as proxy revoked."
        )
    } else if proxy_revoked {
        format!(
            "Revoked sandbox {scope} at {when} UTC: the revocation is signed, and the server says it stored it. Its proxy was revoked, so no end can come for it: nothing in the verified log will prove it stopped (`klav proxy sandboxes --ended` shows it as proxy revoked)."
        )
    } else {
        format!(
            "Revoked sandbox {scope} at {when} UTC: the revocation is signed, and the server says it stored it. The server says it denies it access from now on; what proves it stopped is its end, which its proxy signs in the verified log at its next read (every 30 s) and `klav proxy sandboxes` shows, unless the account revoked that proxy: then no end can come, and the list shows it as proxy revoked."
        )
    }
}

/// A later revocation of the same scope stands. For one sandbox, the
/// server says it already covers it: done, and `--wait` does not wait
/// (the line says so). For all, it does not cover the sandboxes issued
/// after it: exit 1.
fn not_applied(
    scope: String,
    later_at: i64,
    wait: bool,
    json: bool,
    proxy_revoked: bool,
) -> CliResult<()> {
    let all = scope == SCOPE_ALL;
    if json {
        output::json_line(&RevokeView::NotApplied { scope, later_at })?;
    } else if all {
        output::warn(&format!(
            "Not applied: the server has a later «revoke all» of this proxy, signed at {} UTC, ahead of this device's clock. It does not cover sandboxes issued after it: revoke again once this device's clock is past it.",
            minutes(later_at)
        ));
    } else {
        output::line(&not_applied_words(&scope, later_at, wait, proxy_revoked));
    }
    if all { Err(CliError::Exit(1)) } else { Ok(()) }
}

fn not_applied_words(scope: &str, later_at: i64, wait: bool, proxy_revoked: bool) -> String {
    let (shows, waited) = if proxy_revoked {
        (
            "`klav proxy sandboxes --ended` shows it as proxy revoked: its proxy was revoked, so no end can come for it.",
            " Not waited: no end can come.",
        )
    } else {
        (
            "`klav proxy sandboxes` shows it as revoking, or as proxy revoked if the account revoked its proxy.",
            " Not waited: `klav proxy sandboxes` shows its end once the proxy logs it, if its proxy was not revoked.",
        )
    };
    format!(
        "Not applied: the server says a later revocation of {scope}, signed at {} UTC, already covers it; {shows}{}",
        minutes(later_at),
        if wait { waited } else { "" }
    )
}

fn list_ids(ids: &[SandboxId]) -> String {
    ids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A wait that ran out exits 1, or 3 while the setting is flagged: the
/// security problem is the worse of the two, and it stays said.
fn not_ended_exit(flag: Option<&SecurityFlag>, proxy: AgentId) -> CliError {
    match still_flagged(flag, proxy) {
        Err(e) => e,
        Ok(()) => CliError::Exit(1),
    }
}

/// What `revoke` revokes, and where.
struct Target {
    /// The proxy the revocation goes to.
    proxy: AgentId,
    /// One sandbox, or all of the proxy's.
    target: RevokeTarget,
    /// The list's security flag, when `proxy` came from a verified row
    /// because the account's proxy setting cannot be trusted.
    flag: Option<SecurityFlag>,
    /// The verified row says its proxy was revoked
    /// ([`SandboxStatus::ProxyRevoked`]): no end can come. False also when
    /// no row was read (a whole ID by the setting, `--all`).
    proxy_revoked: bool,
}

/// The proxy and the sandboxes to revoke. A full ID and `--all` name the
/// proxy the account's setting names, without verifying the log, so a
/// server that breaks the verification cannot keep the person from
/// revoking. Only the start of an ID needs the verified list, to find it.
///
/// While an agent's preferences flag the setting, nothing in it is used: a
/// full ID or the start of one revokes at the proxy the verified log names
/// for that sandbox, and only a sandbox the verified log lists. `--all` has
/// no row to name its proxy, so it still refuses (exit 3).
async fn target(ctx: &mut Ctx, args: &ProxySandboxRevokeArgs) -> CliResult<Target> {
    let given = match (&args.id, args.all) {
        (None, true) => None,
        (Some(id), false) => Some(id.trim().to_ascii_lowercase()),
        _ => return Err(usage("give a sandbox ID or `--all`")),
    };
    if let Some(id) = given.as_deref().and_then(|s| s.parse::<SandboxId>().ok()) {
        return match account_proxy(ctx).await {
            Ok(proxy) => Ok(Target {
                proxy,
                target: RevokeTarget::One(id),
                flag: None,
                proxy_revoked: false,
            }),
            Err(e) if e.exit_code() == EXIT_SECURITY => by_verified_row(ctx, id, e).await,
            Err(e) => Err(e),
        };
    }
    let Some(prefix) = given else {
        return Ok(Target {
            proxy: account_proxy(ctx).await.map_err(all_hint)?,
            target: RevokeTarget::All,
            flag: None,
            proxy_revoked: false,
        });
    };
    if prefix.chars().count() < SHORT_ID
        || !prefix.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return Err(usage(format!(
            "not a sandbox ID: give it whole or its first {SHORT_ID} characters, as `klav proxy sandboxes` shows them"
        )));
    }
    let list = match flagged_list(ctx).await {
        Ok(list) => list,
        Err((e, older)) => return Err(whole_id_hint(ctx, e, older).await),
    };
    let row = one_row(&list, |r| r.sandbox_id.to_string().starts_with(&prefix))
        .map_err(|found| not_one(found, &prefix, list.security.as_ref()))?;
    Ok(Target::of_row(row, list.security.clone()))
}

/// Why the start of an ID names no row to revoke. While the setting is
/// flagged, exit 3 with the flag, in words that do not lean on the
/// account's proxy, which is not trusted then.
fn not_one(found: Found, prefix: &str, flag: Option<&SecurityFlag>) -> CliError {
    let Some(flag) = flag else {
        return match found {
            Found::None => usage(format!(
                "no sandbox of the account's proxy starts with {prefix} (`klav proxy sandboxes --ended`)"
            )),
            Found::Several => usage(format!(
                "several sandboxes start with {prefix}: give more of the ID"
            )),
            Found::Ended(id) => CliError::Other(format!("sandbox {id} already ended")),
        };
    };
    flagged_refusal(
        flag,
        &match found {
            Found::None => format!(
                "no sandbox in the verified log starts with {prefix} (`klav proxy sandboxes --ended`)"
            ),
            Found::Several => format!(
                "several sandboxes in the verified log start with {prefix}: give more of the ID"
            ),
            Found::Ended(id) => format!("sandbox {id} already ended"),
        },
    )
}

/// A full ID while [`account_proxy`] fails with a security problem (`e`):
/// when that problem is the setting an agent's preferences flag, the proxy
/// of the verified row with that ID. Any other problem, a list that does
/// not verify, or an ID the verified log does not list stays `e`.
async fn by_verified_row(ctx: &mut Ctx, id: SandboxId, e: CliError) -> CliResult<Target> {
    let refused = |next: String| CliError::Coded {
        code: EXIT_SECURITY,
        error: None,
        message: shown(&e.message().unwrap_or_default()),
        next: Some(next),
    };
    let list = match flagged_list(ctx).await {
        Ok(list) => list,
        Err((_, true)) => return Err(refused(OLDER_KLAVD_FLAGGED.into())),
        // While the setting cannot be trusted, a whole ID needs its row
        // in the verified list too: a log that does not verify blocks it.
        Err((list_error, false)) => {
            return Err(refused(format!(
                "a whole ID needs its row in the verified log while the account's proxy setting cannot be trusted, and the list failed ({}): nothing was revoked",
                shown(&list_error.message().unwrap_or_default())
            )));
        }
    };
    let Some(flag) = &list.security else {
        return Err(e);
    };
    match one_row(&list, |r| r.sandbox_id == id) {
        Ok(row) => Ok(Target::of_row(row, list.security.clone())),
        Err(Found::Ended(id)) => Err(flagged_refusal(
            flag,
            &format!("sandbox {id} already ended"),
        )),
        Err(Found::None) => Err(flagged_refusal(
            flag,
            &format!(
                "the verified log lists no sandbox {id}, and the account's proxy setting cannot name its proxy until it is set again (`klav proxy use own <agent>`)"
            ),
        )),
        Err(Found::Several) => Err(flagged_refusal(
            flag,
            &format!(
                "the verified log lists sandbox {id} under more than one proxy, so no one row names where it goes"
            ),
        )),
    }
}

/// Why [`one_row`] found no row to revoke.
#[derive(Debug, PartialEq, Eq)]
enum Found {
    None,
    Several,
    Ended(SandboxId),
}

/// The one row of `list` that `matches`, among the account's proxy's rows,
/// or every proxy's when the list has no proxy (none set, or a flagged
/// setting, which names none): each one from the verified log.
fn one_row(
    list: &SandboxList,
    matches: impl Fn(&SandboxRow) -> bool,
) -> Result<&SandboxRow, Found> {
    let found: Vec<&SandboxRow> = list
        .sandboxes
        .iter()
        .filter(|r| list.proxy.as_ref().is_none_or(|p| r.proxy_id == p.agent_id))
        .filter(|r| matches(r))
        .collect();
    match found.as_slice() {
        [one] if one.status == SandboxStatus::Ended => Err(Found::Ended(one.sandbox_id)),
        [one] => Ok(one),
        [] => Err(Found::None),
        _ => Err(Found::Several),
    }
}

impl Target {
    /// One sandbox, at the proxy its verified row names.
    fn of_row(row: &SandboxRow, flag: Option<SecurityFlag>) -> Self {
        Self {
            proxy: row.proxy_id,
            target: RevokeTarget::One(row.sandbox_id),
            flag,
            proxy_revoked: row.status == SandboxStatus::ProxyRevoked,
        }
    }
}

/// `--all` while the account's setting fails a security check (exit 3):
/// the error says that each sandbox still revokes by its ID.
fn all_hint(e: CliError) -> CliError {
    if e.exit_code() != EXIT_SECURITY {
        return e;
    }
    CliError::Coded {
        code: EXIT_SECURITY,
        error: None,
        message: shown(&e.message().unwrap_or_default()),
        next: Some(
            "`--all` needs the account's proxy, which this setting cannot name now: revoke each sandbox by its ID as `klav proxy sandboxes` lists them, or set the proxy again with `klav proxy use own <agent>`".into(),
        ),
    }
}

/// The start of an ID needs the verified list. When it fails a security
/// check (exit 3), the error says the whole ID revokes without it, but
/// only when it can: while the account's proxy setting cannot be trusted
/// either, a whole ID needs that list too, and an older klavd (`older`)
/// gives no rows at all.
async fn whole_id_hint(ctx: &mut Ctx, e: CliError, older: bool) -> CliError {
    if e.exit_code() != EXIT_SECURITY {
        return e;
    }
    let blocked = matches!(account_proxy(ctx).await, Err(p) if p.exit_code() == EXIT_SECURITY);
    hinted(e, blocked.then_some(older))
}

/// [`whole_id_hint`]'s words: `blocked` when the account's proxy setting
/// cannot be trusted either, with whether the klavd is older.
fn hinted(e: CliError, blocked: Option<bool>) -> CliError {
    if e.exit_code() != EXIT_SECURITY {
        return e;
    }
    let next = match blocked {
        Some(older) => whole_id_blocked(older),
        None => "give the whole ID to revoke without the list (`klav proxy sandboxes revoke <id>`)",
    };
    CliError::Coded {
        code: EXIT_SECURITY,
        error: None,
        message: shown(&e.message().unwrap_or_default()),
        next: Some(next.to_owned()),
    }
}

/// [`whole_id_hint`] when the account's proxy setting cannot be trusted.
fn whole_id_blocked(older: bool) -> &'static str {
    if older {
        OLDER_KLAVD_FLAGGED
    } else {
        "nothing was revoked, and a whole ID would not revoke either: while the account's proxy setting cannot be trusted it needs its row in the verified log, which does not verify; set the proxy again with `klav proxy use own <agent>`"
    }
}

/// The proxy the account's setting names.
async fn account_proxy(ctx: &mut Ctx) -> CliResult<AgentId> {
    let status = super::proxy::status(ctx).await?;
    match (status.mode, status.agent_id) {
        (ProxyMode::Own | ProxyMode::Klav, Some(id)) => Ok(id),
        _ => Err(CliError::Other(
            "The account has no proxy of its own (`klav proxy status`): give the first 8 characters of the ID as `klav proxy sandboxes` shows them, or set the proxy with `klav proxy use own <agent>`.".into(),
        )),
    }
}

/// A sandbox `--wait` stops waiting for, as its proxy was revoked.
fn proxy_revoked_words(id: SandboxId) -> String {
    format!(
        "Sandbox {id}: its proxy was revoked, so it can never log its end, and nothing in the verified log proves it stopped (`klav proxy sandboxes --ended` shows it as proxy revoked)."
    )
}

/// What `--wait` waits on: the sandboxes the person named or the server
/// said it covers, and for an `all`, also every verified row of the proxy
/// that this revocation or a later one covered (`revoked_by_person_at` is
/// its `at` or after), which the server's list may have left out.
struct Waiting {
    ids: Vec<SandboxId>,
    all_at: Option<(AgentId, i64)>,
}

/// What a wait leaves: the sandboxes [`Waiting`] names whose end is not
/// logged, and of those, the ones whose proxy was revoked, which no wait
/// can end.
struct WaitEnd {
    open: Vec<SandboxId>,
    proxy_revoked: Vec<SandboxId>,
}

/// Waits until the proxy has logged the end of every sandbox [`Waiting`]
/// names, or each one left has a revoked proxy
/// ([`SandboxStatus::ProxyRevoked`], which can never end), or
/// [`WAIT_LIMIT`]; returns those still not ended. The revocation
/// is already applied and said: a list that cannot be read stops the wait
/// with a warning and counts the rest as not ended, except a security
/// failure (a log that does not verify), which is this command's error,
/// exit 3. With `flagged`, the flag the revocation was made under is not
/// such a failure: [`revoke_cmd`] says it once the wait is over.
async fn wait_for_ends(ctx: &mut Ctx, waiting: &Waiting, flagged: bool) -> CliResult<WaitEnd> {
    let deadline = Instant::now() + WAIT_LIMIT;
    let mut open = waiting.ids.clone();
    let mut proxy_revoked = Vec::new();
    loop {
        // A revocation made while the setting is flagged waits on the
        // verified rows of the flagged list; any other on the plain list.
        let read = if flagged {
            the_flagged_list(ctx).await
        } else {
            the_list(ctx).await
        };
        match read {
            Ok(list) => {
                open = not_ended(&list, waiting);
                proxy_revoked = of_revoked_proxies(&list, &open);
            }
            Err(e) if e.exit_code() == EXIT_SECURITY => return Err(e),
            Err(e) => {
                output::warn(&format!(
                    "Stopped waiting: the list could not be read ({}).",
                    shown(&e.message().unwrap_or_default())
                ));
                return Ok(WaitEnd {
                    open,
                    proxy_revoked,
                });
            }
        }
        if proxy_revoked.len() == open.len() || Instant::now() >= deadline {
            return Ok(WaitEnd {
                open,
                proxy_revoked,
            });
        }
        tokio::time::sleep(WAIT_EVERY).await;
    }
}

/// Those of `open` whose verified row says their proxy was revoked.
fn of_revoked_proxies(list: &SandboxList, open: &[SandboxId]) -> Vec<SandboxId> {
    open.iter()
        .filter(|id| {
            list.sandboxes
                .iter()
                .any(|r| r.sandbox_id == **id && r.status == SandboxStatus::ProxyRevoked)
        })
        .copied()
        .collect()
}

/// The sandboxes [`Waiting`] names whose end the verified list does not
/// show: an unknown status is not an end, nor is a revoked proxy.
fn not_ended(list: &SandboxList, waiting: &Waiting) -> Vec<SandboxId> {
    let mut wanted = waiting.ids.clone();
    if let Some((proxy, at)) = waiting.all_at {
        for r in &list.sandboxes {
            if r.proxy_id == proxy
                && r.revoked_by_person_at.is_some_and(|t| t >= at)
                && !wanted.contains(&r.sandbox_id)
            {
                wanted.push(r.sandbox_id);
            }
        }
    }
    wanted
        .into_iter()
        .filter(|id| {
            !list
                .sandboxes
                .iter()
                .any(|r| r.sandbox_id == *id && r.status == SandboxStatus::Ended)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: SandboxStatus, proxy_id: AgentId) -> SandboxRow {
        SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id,
            issuer_id: AgentId::generate(),
            issuer_name: Some("t3\u{1b}[31m-code".into()),
            label: "chat\u{202e}-1\n".into(),
            profiles: vec!["rail\u{7}way".into()],
            issued_at: 1,
            expires_at: 2,
            claimed_at: None,
            status,
            end_reason: None,
            ended_at: None,
            revoked_by_person_at: None,
            proxy_revoked_at: None,
            connected: None,
            last_seen_at: None,
        }
    }

    /// A list as the flagged read gives it: no proxy (the setting is not
    /// used), every proxy's verified rows, and the flag.
    fn flagged(sandboxes: Vec<SandboxRow>) -> SandboxList {
        SandboxList {
            proxy: None,
            sandboxes,
            verified_events: 9,
            warnings: Vec::new(),
            marks_unreadable: false,
            security: Some(SecurityFlag::PreferencesByAgent {
                agent_id: AgentId::generate(),
            }),
        }
    }

    /// While flagged, a revocation goes to the proxy of the verified row
    /// it names, whichever proxy that is; only a verified row, and never
    /// an ended one, is revoked this way.
    #[test]
    fn a_flagged_revocation_takes_the_proxy_of_its_verified_row() {
        let (mine, former) = (AgentId::generate(), AgentId::generate());
        let live = row(SandboxStatus::Active, mine);
        let old = row(SandboxStatus::Waiting, former);
        let ended = row(SandboxStatus::Ended, mine);
        let list = flagged(vec![live.clone(), old.clone(), ended.clone()]);
        for r in [&live, &old] {
            let found = one_row(&list, |x| x.sandbox_id == r.sandbox_id).expect("found");
            let t = Target::of_row(found, list.security.clone());
            assert_eq!(t.proxy, r.proxy_id);
            assert_eq!(t.target, RevokeTarget::One(r.sandbox_id));
            assert_eq!(t.flag, list.security);
        }
        assert_eq!(
            one_row(&list, |x| x.sandbox_id == ended.sandbox_id).err(),
            Some(Found::Ended(ended.sandbox_id))
        );
        let unknown = SandboxId::generate();
        assert_eq!(
            one_row(&list, |x| x.sandbox_id == unknown).err(),
            Some(Found::None)
        );
        assert_eq!(one_row(&list, |_| true).err(), Some(Found::Several));
        // With the account's proxy known, another proxy's row is not one.
        let mut trusted = list.clone();
        trusted.security = None;
        trusted.proxy = Some(ProxyView {
            agent_id: mine,
            name: None,
            paused: false,
            heartbeat_sent_at: None,
            heartbeat_age_ms: None,
            quiet: true,
            no_signs: None,
        });
        assert_eq!(
            one_row(&trusted, |x| x.sandbox_id == old.sandbox_id).err(),
            Some(Found::None)
        );
    }

    /// A revocation made under the flag ends with it: exit 3, the flag's
    /// words, and where the revocation went. Without a flag, nothing.
    #[test]
    fn a_revocation_under_the_flag_still_exits_3() {
        let proxy = AgentId::generate();
        assert!(still_flagged(None, proxy).is_ok());
        let agent = AgentId::generate();
        let e = still_flagged(
            Some(&SecurityFlag::PreferencesByAgent { agent_id: agent }),
            proxy,
        )
        .expect_err("flagged");
        assert_eq!(e.exit_code(), EXIT_SECURITY);
        let CliError::Coded { message, next, .. } = &e else {
            panic!("{e:?}");
        };
        assert!(message.contains(&agent.to_string()), "{message}");
        assert!(
            next.as_deref().is_some_and(|n| n.contains(&format!(
                "went to proxy {proxy}, the one the verified log names"
            ))),
            "{next:?}"
        );
    }

    /// A wait that runs out exits 1, or 3 under the flag, naming the proxy.
    #[test]
    fn a_wait_that_runs_out_under_the_flag_exits_3_not_1() {
        let proxy = AgentId::generate();
        assert_eq!(not_ended_exit(None, proxy).exit_code(), 1);
        let flag = SecurityFlag::PreferencesByAgent {
            agent_id: AgentId::generate(),
        };
        let e = not_ended_exit(Some(&flag), proxy);
        assert_eq!(e.exit_code(), EXIT_SECURITY);
        assert!(
            e.message().is_some_and(|m| m.contains(&proxy.to_string())),
            "{e:?}"
        );
    }

    /// Under the flag, the start of an ID that names no row, several or an
    /// ended one exits 3 with the flag's words, the reason, and that
    /// nothing was revoked, never leaning on the account's proxy; without
    /// it, the codes and words are as before (2, 2, 1).
    #[test]
    fn a_prefix_that_names_no_row_under_the_flag_exits_3() {
        let writer = AgentId::generate();
        let flag = SecurityFlag::PreferencesByAgent { agent_id: writer };
        let id = SandboxId::generate();
        for (found, why) in [
            (
                Found::None,
                "no sandbox in the verified log starts with 0123abcd",
            ),
            (
                Found::Several,
                "several sandboxes in the verified log start with 0123abcd",
            ),
            (Found::Ended(id), &*format!("sandbox {id} already ended")),
        ] {
            let e = not_one(found, "0123abcd", Some(&flag));
            assert_eq!(e.exit_code(), EXIT_SECURITY, "{e:?}");
            let m = e.message().expect("words");
            assert!(m.contains(&writer.to_string()), "{m}");
            assert!(m.contains(why), "{m}");
            assert!(m.contains("nothing was revoked"), "{m}");
            assert!(!m.contains("account's proxy starts"), "{m}");
        }
        assert_eq!(not_one(Found::None, "0123abcd", None).exit_code(), 2);
        assert_eq!(not_one(Found::Several, "0123abcd", None).exit_code(), 2);
        assert_eq!(not_one(Found::Ended(id), "0123abcd", None).exit_code(), 1);
    }

    /// Any other failure after a flagged target exits 3 with the flag and
    /// keeps its own words; one that already exits 3 is left as it is.
    #[test]
    fn any_failure_under_the_flag_exits_3() {
        let writer = AgentId::generate();
        let flag = SecurityFlag::PreferencesByAgent { agent_id: writer };
        let e = under_flag(&flag, CliError::Other("the server is down".into()));
        assert_eq!(e.exit_code(), EXIT_SECURITY);
        let m = e.message().expect("words");
        assert!(
            m.contains(&writer.to_string()) && m.contains("the server is down"),
            "{m}"
        );
        let e = under_flag(&flag, CliError::Exit(1));
        assert_eq!(e.exit_code(), EXIT_SECURITY);
        let kept = under_flag(
            &flag,
            CliError::Coded {
                code: EXIT_SECURITY,
                error: None,
                message: "already".into(),
                next: None,
            },
        );
        assert_eq!(kept.message().as_deref(), Some("already"));
    }

    /// While the setting cannot be trusted, the hint never sends the person
    /// to a whole ID: an older klavd needs updating, and otherwise the
    /// setting needs setting again.
    #[test]
    fn a_whole_id_is_not_offered_when_it_cannot_revoke() {
        for older in [true, false] {
            let n = whole_id_blocked(older);
            assert!(!n.contains("give the whole ID"), "{n}");
            assert!(n.contains("klav proxy use own"), "{n}");
            assert!(n.contains("nothing was revoked"), "{n}");
        }
        assert!(whole_id_blocked(true).contains("update klavd"));
    }

    /// `--all` under a security problem keeps its exit 3 and its words, and
    /// says each sandbox still revokes by its ID; any other error is as it
    /// was.
    #[test]
    fn revoke_all_under_a_security_problem_points_to_each_id() {
        let e = all_hint(CliError::Client(klav_client::ClientError::Security(
            "preferences".into(),
        )));
        assert_eq!(e.exit_code(), EXIT_SECURITY);
        let CliError::Coded { message, next, .. } = &e else {
            panic!("{e:?}");
        };
        assert!(message.contains("preferences"), "{message}");
        assert!(
            next.as_deref()
                .is_some_and(|n| n.contains("revoke each sandbox by its ID")),
            "{next:?}"
        );
        let other = all_hint(CliError::Other("down".into()));
        assert_eq!(other.exit_code(), 1);
        assert!(matches!(other, CliError::Other(_)));
    }

    /// Only the account's proxy's rows, every text on one clean line.
    #[test]
    fn the_list_is_the_account_proxys_with_clean_text() {
        let proxy = AgentId::generate();
        let list = SandboxList {
            proxy: Some(ProxyView {
                agent_id: proxy,
                name: Some("klav\u{1b}]0;x\u{7}-proxy".into()),
                paused: false,
                heartbeat_sent_at: None,
                heartbeat_age_ms: None,
                quiet: true,
                no_signs: Some(NoSigns::NoHeartbeat),
            }),
            sandboxes: vec![
                row(SandboxStatus::Active, AgentId::generate()),
                row(SandboxStatus::Waiting, proxy),
            ],
            verified_events: 3,
            warnings: vec!["w\u{1b}[2J".into()],
            marks_unreadable: false,
            security: None,
        };
        let list = of_account_proxy(list);
        assert_eq!(list.sandboxes.len(), 1);
        let r = &list.sandboxes[0];
        assert_eq!(r.proxy_id, proxy);
        for text in [
            r.label.as_str(),
            r.issuer_name.as_deref().unwrap_or(""),
            r.profiles[0].as_str(),
            list.proxy
                .as_ref()
                .and_then(|p| p.name.as_deref())
                .unwrap_or(""),
            list.warnings[0].as_str(),
        ] {
            assert!(!text.chars().any(klav_core::text::is_hidden), "{text:?}");
        }
    }

    /// Every end reason and status reads as the person's words (the
    /// glossary records them), and only an end logged by the proxy counts as ended
    /// for `--wait`: an unknown status is shown as unknown and waited on.
    #[test]
    fn states_read_as_words_and_only_a_logged_end_is_an_end() {
        let proxy = AgentId::generate();
        let mut ended = row(SandboxStatus::Ended, proxy);
        ended.end_reason = Some(EndReason::Theft);
        ended.ended_at = Some(0);
        assert_eq!(state(&ended), "theft signal (00:00 UTC)");
        let mut revoking = row(SandboxStatus::Revoking, proxy);
        revoking.revoked_by_person_at = Some(60_000);
        assert_eq!(state(&revoking), "revoking (revoked 00:01 UTC)");
        assert_eq!(
            state(&row(SandboxStatus::Waiting, proxy)),
            "waiting for claim"
        );
        let unknown = row(SandboxStatus::Unknown, proxy);
        assert_eq!(state(&unknown), "unknown state: update klav");
        let list = SandboxList {
            proxy: None,
            sandboxes: vec![ended.clone(), revoking.clone(), unknown.clone()],
            verified_events: 1,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        let other = SandboxId::generate();
        let waiting = |ids: Vec<SandboxId>| Waiting { ids, all_at: None };
        assert_eq!(
            not_ended(
                &list,
                &waiting(vec![ended.sandbox_id, revoking.sandbox_id, other])
            ),
            [revoking.sandbox_id, other]
        );
        assert_eq!(
            not_ended(&list, &waiting(vec![unknown.sandbox_id])),
            [unknown.sandbox_id]
        );
        assert!(counts_line(&list).contains("1 of a state this klav does not know"));
    }

    /// A row whose proxy was revoked reads as that, never as ended, and
    /// with the time; the plain list hides it, as an ended one, `--ended`
    /// shows it, and the account's live counts leave it out. `--wait`
    /// stops waiting for it, and keeps it among the not ended.
    #[test]
    fn a_revoked_proxys_row_is_settled_but_never_ended() {
        let proxy = AgentId::generate();
        let mut gone = row(SandboxStatus::ProxyRevoked, proxy);
        gone.revoked_by_person_at = Some(30_000);
        gone.proxy_revoked_at = Some(60_000);
        assert_eq!(
            state(&gone),
            "proxy revoked: its end can no longer be logged (proxy revoked 00:01 UTC)"
        );
        gone.proxy_revoked_at = None;
        assert_eq!(
            state(&gone),
            "proxy revoked: its end can no longer be logged"
        );
        let live = row(SandboxStatus::Active, proxy);
        let list = SandboxList {
            proxy: None,
            sandboxes: vec![gone.clone(), live.clone()],
            verified_events: 1,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        let shown: Vec<SandboxId> = listed(list.clone(), false)
            .sandboxes
            .iter()
            .map(|r| r.sandbox_id)
            .collect();
        assert_eq!(shown, [live.sandbox_id]);
        assert_eq!(listed(list.clone(), true).sandboxes.len(), 2);
        assert!(
            counts_line(&list).starts_with("Sandboxes: 1 active"),
            "{}",
            counts_line(&list)
        );
        let waiting = Waiting {
            ids: vec![gone.sandbox_id, live.sandbox_id],
            all_at: None,
        };
        let open = not_ended(&list, &waiting);
        assert_eq!(open, [gone.sandbox_id, live.sandbox_id]);
        assert_eq!(of_revoked_proxies(&list, &open), [gone.sandbox_id]);
        assert!(
            proxy_revoked_words(gone.sandbox_id)
                .contains("its proxy was revoked, so it can never log its end")
        );
    }

    /// `--wait` after an `all` also waits on the verified rows of the proxy
    /// that this revocation or a later one covered, even when the server's
    /// list left one out; a row an earlier revocation covered, or another
    /// proxy's, is not waited on.
    #[test]
    fn an_alls_wait_takes_the_verified_rows_it_covered() {
        let proxy = AgentId::generate();
        let at = 60_000;
        let mut left_out = row(SandboxStatus::Revoking, proxy);
        left_out.revoked_by_person_at = Some(at);
        let mut earlier = row(SandboxStatus::Revoking, proxy);
        earlier.revoked_by_person_at = Some(at - 1);
        let mut later = row(SandboxStatus::Revoking, proxy);
        later.revoked_by_person_at = Some(at + 1);
        let mut elsewhere = row(SandboxStatus::Revoking, AgentId::generate());
        elsewhere.revoked_by_person_at = Some(at);
        let mut done = row(SandboxStatus::Ended, proxy);
        done.revoked_by_person_at = Some(at);
        let list = SandboxList {
            proxy: None,
            sandboxes: vec![
                left_out.clone(),
                earlier,
                later.clone(),
                elsewhere,
                done.clone(),
            ],
            verified_events: 1,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        let listed = SandboxId::generate();
        let waiting = Waiting {
            ids: vec![listed, done.sandbox_id],
            all_at: Some((proxy, at)),
        };
        assert_eq!(
            not_ended(&list, &waiting),
            [listed, left_out.sandbox_id, later.sandbox_id]
        );
    }

    /// A later revocation of the same scope: done for one sandbox (exit
    /// 0), exit 1 for `all`, which does not cover what was issued after it.
    /// The line gives the server's word as its word, and under `--wait`
    /// says it did not wait.
    #[test]
    fn not_applied_is_done_for_one_and_exit_1_for_all() {
        let id = SandboxId::generate();
        assert!(not_applied(id.to_string(), 60_000, true, false, false).is_ok());
        assert!(matches!(
            not_applied(SCOPE_ALL.to_owned(), 60_000, false, false, false),
            Err(CliError::Exit(1))
        ));
        let line = |wait| not_applied_words(&id.to_string(), 60_000, wait, false);
        assert_eq!(
            line(false),
            format!(
                "Not applied: the server says a later revocation of {id}, signed at 00:01 UTC, already covers it; `klav proxy sandboxes` shows it as revoking, or as proxy revoked if the account revoked its proxy."
            )
        );
        assert!(line(true).starts_with(&line(false)));
        assert!(line(true).ends_with(
            " Not waited: `klav proxy sandboxes` shows its end once the proxy logs it, if its proxy was not revoked."
        ));
        // Its verified row says its proxy was revoked: no end can come.
        let gone = |wait| not_applied_words(&id.to_string(), 60_000, wait, true);
        assert_eq!(
            gone(true),
            format!(
                "Not applied: the server says a later revocation of {id}, signed at 00:01 UTC, already covers it; `klav proxy sandboxes --ended` shows it as proxy revoked: its proxy was revoked, so no end can come for it. Not waited: no end can come."
            )
        );
        assert!(!gone(false).contains("as revoking"));
    }

    /// The revocation's line says what was signed and gives the rest as
    /// the server's word, also for an `all` that covered nothing live.
    #[test]
    fn revoked_lines_give_the_servers_word_as_its_word() {
        let id = SandboxId::generate();
        let one = revoked_words(&id.to_string(), &[id], 60_000, false);
        assert!(
            one.starts_with(&format!(
                "Revoked sandbox {id} at 00:01 UTC: the revocation is signed, and the server says it stored it. The server says it denies it access from now on; "
            )),
            "{one}"
        );
        // Without a row read, it says a revoked proxy gives no end.
        assert!(
            one.ends_with(
                ", unless the account revoked that proxy: then no end can come, and the list shows it as proxy revoked."
            ),
            "{one}"
        );
        // Its verified row says its proxy was revoked: no end is promised.
        let gone = revoked_words(&id.to_string(), &[id], 60_000, true);
        assert_eq!(
            gone,
            format!(
                "Revoked sandbox {id} at 00:01 UTC: the revocation is signed, and the server says it stored it. Its proxy was revoked, so no end can come for it: nothing in the verified log will prove it stopped (`klav proxy sandboxes --ended` shows it as proxy revoked)."
            )
        );
        assert!(!gone.contains("next read"), "{gone}");
        let all = |ids: &[SandboxId]| revoked_words(SCOPE_ALL, ids, 60_000, false);
        assert!(
            all(&[]).ends_with(
                ", unless the account revoked that proxy: then no end can come, and the list shows them as proxy revoked."
            ),
            "{}",
            all(&[])
        );
        assert!(
            all(&[]).contains(
                "the server says it stored it and it covers no live sandbox. The server says it denies them access"
            ),
            "{}",
            all(&[])
        );
        assert!(
            all(&[id]).contains(&format!(
                "the server says it stored it and it covers {id}. "
            )),
            "{}",
            all(&[id])
        );
    }

    /// A short ID needs the verified list: when the log does not verify,
    /// the error keeps exit 3 and its text, and says the whole ID revokes
    /// without the list. Any other error passes unchanged.
    #[test]
    fn a_short_id_on_a_log_that_does_not_verify_points_to_the_whole_id() {
        let rewritten = || {
            CliError::Client(klav_client::ClientError::Security(
                "the chain was rewritten".into(),
            ))
        };
        let failed = hinted(rewritten(), None);
        assert_eq!(failed.exit_code(), EXIT_SECURITY);
        let text = failed.message().unwrap_or_default();
        assert!(
            text.starts_with("SECURITY: the chain was rewritten\nNext: "),
            "{text}"
        );
        assert!(
            text.ends_with(
                "\nNext: give the whole ID to revoke without the list (`klav proxy sandboxes revoke <id>`)"
            ),
            "{text}"
        );
        let other = hinted(CliError::Other("offline".into()), Some(true));
        assert!(matches!(other, CliError::Other(m) if m == "offline"));
        // While the setting cannot be trusted either, no whole ID.
        for older in [true, false] {
            let text = hinted(rewritten(), Some(older))
                .message()
                .unwrap_or_default();
            assert!(
                text.starts_with("SECURITY: the chain was rewritten"),
                "{text}"
            );
            assert!(text.ends_with(whole_id_blocked(older)), "{text}");
        }
    }

    /// A rollback of the proxy's heartbeat reads as a security warning,
    /// not as a quiet proxy; other reasons stay «no signs».
    #[test]
    fn a_heartbeat_rollback_reads_as_a_security_warning() {
        let view = |why| ProxyView {
            agent_id: AgentId::generate(),
            name: Some("klav-proxy".into()),
            paused: false,
            heartbeat_sent_at: None,
            heartbeat_age_ms: None,
            quiet: true,
            no_signs: Some(why),
        };
        let rollback = proxy_line(&view(NoSigns::Rollback));
        assert!(
            rollback.ends_with(
                ": security warning: the server sent an older heartbeat than this device has seen, as a server rolling it back would; its heartbeat is not shown"
            ),
            "{rollback}"
        );
        assert!(!rollback.contains("no signs"), "{rollback}");
        assert!(proxy_line(&view(NoSigns::NoHeartbeat)).ends_with(": no signs (no heartbeat yet)"));
    }

    /// `klav proxy status` says a heartbeat rollback in the same line as
    /// `klav proxy sandboxes`, above the counts, and nothing else of the
    /// list's warnings (an agent's event after its revocation is one); any
    /// other «no signs» is the counts alone.
    #[test]
    fn status_says_a_heartbeat_rollback_as_the_list_does() {
        let proxy = AgentId::generate();
        let list = |why| SandboxList {
            proxy: Some(ProxyView {
                agent_id: proxy,
                name: Some("klav-proxy".into()),
                paused: false,
                heartbeat_sent_at: None,
                heartbeat_age_ms: None,
                quiet: true,
                no_signs: Some(why),
            }),
            sandboxes: vec![row(SandboxStatus::Active, proxy)],
            verified_events: 9,
            warnings: vec![format!(
                "event 8 (agent.access): agent {proxy} acted after its revocation"
            )],
            marks_unreadable: false,
            security: None,
        };
        let rolled = list(NoSigns::Rollback);
        let lines = status_lines(&rolled);
        let shown = rolled.proxy.as_ref().expect("proxy");
        assert_eq!(
            lines,
            [
                format!("Proxy: {}", proxy_line(shown)),
                counts_line(&rolled)
            ]
        );
        assert!(lines[0].contains(": security warning: "), "{lines:?}");
        assert!(
            lines.iter().all(|l| !l.contains("acted after")),
            "{lines:?}"
        );
        for why in [NoSigns::NoHeartbeat, NoSigns::OtherEpoch, NoSigns::Unknown] {
            let quiet = list(why);
            assert_eq!(status_lines(&quiet), [counts_line(&quiet)]);
        }
        let none = SandboxList {
            proxy: None,
            ..list(NoSigns::Rollback)
        };
        assert_eq!(status_lines(&none), [counts_line(&none)]);
    }

    /// A list with one theft, one ordinary end and one live row of the
    /// account's proxy, cleaned as the list shows it.
    fn with_a_theft() -> (SandboxList, SandboxId) {
        let proxy = AgentId::generate();
        let mut theft = row(SandboxStatus::Ended, proxy);
        theft.end_reason = Some(EndReason::Theft);
        theft.ended_at = Some(1_794_594_120_000);
        let id = theft.sandbox_id;
        let mut stopped = row(SandboxStatus::Ended, proxy);
        stopped.end_reason = Some(EndReason::Stop);
        let list = SandboxList {
            proxy: None,
            sandboxes: vec![stopped, theft, row(SandboxStatus::Active, proxy)],
            verified_events: 9,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        (of_account_proxy(list), id)
    }

    /// The plain list keeps the rows the theft signal ended, and only
    /// those of the ended ones; `--json` names them in `theft_signals`,
    /// there also when empty.
    #[test]
    fn the_plain_list_never_hides_a_theft() {
        let (list, id) = with_a_theft();
        let plain = listed(list.clone(), false);
        let states: Vec<SandboxStatus> = plain.sandboxes.iter().map(|r| r.status).collect();
        assert_eq!(states, [SandboxStatus::Ended, SandboxStatus::Active]);
        assert_eq!(plain.sandboxes[0].sandbox_id, id);
        let doc = serde_json::to_value(ListJson::of(&plain)).expect("json");
        assert_eq!(doc["theft_signals"], serde_json::json!([id]), "{doc}");
        assert_eq!(doc["sandboxes"][0]["end_reason"], "theft", "{doc}");
        assert_eq!(doc["verified_events"], 9, "{doc}");
        assert_eq!(listed(list.clone(), true).sandboxes.len(), 3);
        let none = listed(
            SandboxList {
                sandboxes: vec![row(SandboxStatus::Active, AgentId::generate())],
                ..list
            },
            false,
        );
        let doc = serde_json::to_value(ListJson::of(&none)).expect("json");
        assert_eq!(doc["theft_signals"], serde_json::json!([]), "{doc}");
    }

    /// A theft reads as a security warning, never as an ordinary end, with
    /// the sandbox, its label and issuer cleaned, and what to do; `klav
    /// proxy status` says it in the same line, above the counts.
    #[test]
    fn a_theft_reads_as_a_security_warning_in_the_list_and_the_status() {
        let (list, id) = with_a_theft();
        let theft = list.thefts()[0];
        let line = theft_line(theft);
        let short: String = id.to_string().chars().take(SHORT_ID).collect();
        assert!(
            line.starts_with(&format!(
                "Sandbox {short}: security warning: theft signal at "
            )),
            "{line}"
        );
        assert!(
            line.contains("\"chat-1\" (per the issuer; issuer t3[31m-code ("),
            "{line}"
        );
        assert!(
            line.contains(&format!("klav agent pause {}", theft.issuer_id)),
            "{line}"
        );
        assert!(!line.chars().any(char::is_control), "{line}");
        assert_eq!(
            state(theft),
            format!("theft signal ({} UTC)", minutes(1_794_594_120_000))
        );
        let lines = status_lines(&list);
        assert_eq!(lines, [line, counts_line(&list)]);
    }

    /// Above the table: the proxy, the list's warnings, then each theft
    /// line; an ordinary end has none.
    #[test]
    fn the_list_says_each_theft_above_its_table() {
        let (mut list, id) = with_a_theft();
        list.warnings = vec!["event 8 (agent.access): an agent acted after its revocation".into()];
        let theft = list.thefts()[0];
        assert_eq!(theft.sandbox_id, id);
        assert_eq!(
            header_lines(&list),
            [
                Header::Out(
                    "Proxy: none (`klav proxy use own <agent>`). Below, the sandboxes of every proxy in the log."
                        .into()
                ),
                Header::Warn(list.warnings[0].clone()),
                Header::Out(theft_line(theft)),
            ]
        );
        let calm = SandboxList {
            sandboxes: list
                .sandboxes
                .iter()
                .filter(|r| !r.is_theft())
                .cloned()
                .collect(),
            warnings: vec![],
            ..list.clone()
        };
        assert_eq!(header_lines(&calm).len(), 1);
    }

    /// Two thefts are two lines, in the order the sandboxes were issued
    /// (the list's order), not the order they ended, in the list and in
    /// `klav proxy status`.
    #[test]
    fn two_thefts_are_two_lines_in_the_order_they_were_issued() {
        let proxy = AgentId::generate();
        let theft = |label: &str, ended_at: i64| {
            let mut r = row(SandboxStatus::Ended, proxy);
            r.label = label.into();
            r.end_reason = Some(EndReason::Theft);
            r.ended_at = Some(ended_at);
            r
        };
        // Issued first, ended last.
        let first = theft("deploy", 1_794_594_180_000);
        let second = theft("migrate", 1_794_594_120_000);
        let list = of_account_proxy(SandboxList {
            proxy: None,
            sandboxes: vec![
                first.clone(),
                row(SandboxStatus::Active, proxy),
                second.clone(),
            ],
            verified_events: 12,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        });
        let ids: Vec<SandboxId> = list.thefts().iter().map(|r| r.sandbox_id).collect();
        assert_eq!(ids, [first.sandbox_id, second.sandbox_id]);
        let [one, two] = [&list.sandboxes[0], &list.sandboxes[2]].map(theft_line);
        assert!(one.contains("\"deploy\""), "{one}");
        assert!(two.contains("\"migrate\""), "{two}");
        let header = header_lines(&list);
        assert_eq!(
            header[1..],
            [Header::Out(one.clone()), Header::Out(two.clone())]
        );
        assert_eq!(status_lines(&list), [one, two, counts_line(&list)]);
        let doc = serde_json::to_value(ListJson::of(&listed(list, false))).expect("json");
        assert_eq!(
            doc["theft_signals"],
            serde_json::json!([first.sandbox_id, second.sandbox_id]),
            "{doc}"
        );
    }

    #[test]
    fn ages_read_as_words() {
        assert_eq!(ago(-5), "just now");
        assert_eq!(ago(59_999), "just now");
        assert_eq!(ago(120_000), "2 min ago");
        assert_eq!(ago(3 * 3_600_000), "3h ago");
        assert_eq!(ago(3 * 86_400_000), "3 days ago");
    }
}
