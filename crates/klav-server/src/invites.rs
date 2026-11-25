//! `klav-server invite create|ls|revoke` (ADR 0048 §1.4): managing
//! registration invites against the configured database, with no HTTP
//! admin API. Whoever can read and write the database already controls the
//! server, so this adds no privilege.
//!
//! These commands never migrate (see [`Db::connect_existing`]) and run next
//! to a running server (SQLite in WAL with `busy_timeout`, or Postgres).
//! A code is printed once, on stdout, by `create`; only its digest is
//! stored, and it is never logged.

use std::fmt::Write as _;

use klav_core::crypto::invite::InviteCode;
use klav_core::crypto::random;

use crate::config::Config;
use crate::db::{self, Db, now_ms};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const HOUR_MS: i64 = 60 * 60 * 1000;
/// Default lifetime of an invite (`--expires`).
const DEFAULT_EXPIRES_MS: i64 = 30 * DAY_MS;
/// Longest lifetime of a single-use invite.
const MAX_EXPIRES_MS: i64 = 365 * DAY_MS;
/// Batch codes (more than one use): at most this many uses (Q3).
pub const MAX_BATCH_USES: i64 = 50;
/// Batch codes: at most this lifetime, always given explicitly (Q3).
const MAX_BATCH_EXPIRES_MS: i64 = 14 * DAY_MS;
/// Longest note, in characters.
const MAX_NOTE_CHARS: usize = 200;

/// Usage of `klav-server invite`.
pub const USAGE: &str =
    "usage: klav-server invite create [--email EMAIL] [--uses N] [--expires 30d] [--note TEXT]
       klav-server invite ls [--all]
       klav-server invite revoke <ID>
  [--config <path>] works with every subcommand.
  --expires takes days or hours (14d, 36h). More than one use needs --expires, 14d at most,
  and at most 50 uses (a batch code, not bound to an email).";

/// A parsed `invite` subcommand.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Create an invite and print its code once.
    Create(Create),
    /// List invites (without codes); only usable ones unless `all`.
    Ls {
        /// Also revoked, expired and used-up ones.
        all: bool,
    },
    /// Revoke an invite by its `id`.
    Revoke {
        /// The invite's `id` (never its code).
        id: String,
    },
}

/// `invite create`.
#[derive(Debug, PartialEq, Eq)]
pub struct Create {
    /// Only this email can use it (normalized like the server's sign-up).
    pub email: Option<String>,
    /// How many accounts it can create.
    pub uses: i64,
    /// Lifetime from now, in milliseconds.
    pub expires_in_ms: i64,
    /// A note for whoever runs the server; never shown to the person.
    pub note: Option<String>,
}

/// Parses the arguments after `invite` (without `--config`).
pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut args = args.iter();
    let sub = args.next().ok_or_else(|| USAGE.to_owned())?;
    match sub.as_str() {
        "create" => {
            let mut email = None;
            let mut uses = None;
            let mut expires = None;
            let mut note = None;
            while let Some(arg) = args.next() {
                let mut value = |name: &str| {
                    args.next()
                        .cloned()
                        .ok_or_else(|| format!("{name} needs a value\n{USAGE}"))
                };
                match arg.as_str() {
                    "--email" => email = Some(value("--email")?),
                    "--uses" => {
                        let text = value("--uses")?;
                        uses = Some(text.parse::<i64>().ok().filter(|n| *n >= 1).ok_or_else(
                            || format!("--uses must be a whole number from 1, not {text:?}"),
                        )?);
                    }
                    "--expires" => expires = Some(duration_ms(&value("--expires")?)?),
                    "--note" => note = Some(value("--note")?),
                    other => return Err(format!("unknown argument {other}\n{USAGE}")),
                }
            }
            let uses = uses.unwrap_or(1);
            if uses > 1 {
                if email.is_some() {
                    return Err(
                        "--email binds an invite to one account: it can't have more than one use"
                            .into(),
                    );
                }
                if uses > MAX_BATCH_USES {
                    return Err(format!(
                        "a batch code has at most {MAX_BATCH_USES} uses, not {uses}"
                    ));
                }
                match expires {
                    None => {
                        return Err(
                            "more than one use needs --expires (14d at most): a batch code that leaks must run out"
                                .into(),
                        );
                    }
                    Some(ms) if ms > MAX_BATCH_EXPIRES_MS => {
                        return Err("a batch code expires in 14 days (14d) at most".into());
                    }
                    Some(_) => {}
                }
            }
            let expires_in_ms = expires.unwrap_or(DEFAULT_EXPIRES_MS);
            if expires_in_ms > MAX_EXPIRES_MS {
                return Err("an invite expires in 365 days (365d) at most".into());
            }
            let email = match email {
                Some(raw) => Some(
                    crate::validate::email(&raw)
                        .map_err(|_| format!("--email: {raw:?} is not a valid email address"))?,
                ),
                None => None,
            };
            if let Some(n) = &note
                && (n.chars().count() > MAX_NOTE_CHARS || n.chars().any(char::is_control))
            {
                return Err(format!(
                    "--note has at most {MAX_NOTE_CHARS} characters and no control characters"
                ));
            }
            Ok(Command::Create(Create {
                email,
                uses,
                expires_in_ms,
                note,
            }))
        }
        "ls" => match args.next().map(String::as_str) {
            None => Ok(Command::Ls { all: false }),
            Some("--all") if args.next().is_none() => Ok(Command::Ls { all: true }),
            Some(other) => Err(format!("unknown argument {other}\n{USAGE}")),
        },
        "revoke" => match (args.next(), args.next()) {
            (Some(id), None) if !id.starts_with('-') => Ok(Command::Revoke { id: id.clone() }),
            _ => Err(format!("revoke takes one invite ID\n{USAGE}")),
        },
        other => Err(format!("unknown invite subcommand {other}\n{USAGE}")),
    }
}

/// `14d`, `36h`: a positive lifetime in days or hours.
fn duration_ms(text: &str) -> Result<i64, String> {
    let bad = || format!("--expires takes days or hours, like 30d or 36h, not {text:?}");
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let n: i64 = number
        .parse()
        .ok()
        .filter(|n| *n >= 1 && number.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(bad)?;
    let unit = match unit {
        "d" => DAY_MS,
        "h" => HOUR_MS,
        _ => return Err(bad()),
    };
    n.checked_mul(unit).ok_or_else(bad)
}

/// Runs a parsed command against the configured database. `Ok` is what to
/// print on stdout; `Err` is a message for stderr.
pub async fn run(config: &Config, command: Command) -> Result<String, String> {
    check_sqlite_owner(&config.database_url)?;
    let db = Db::connect_existing(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let result = match command {
        Command::Create(create) => create_invite(&db, create).await,
        Command::Ls { all } => list(&db, all).await,
        Command::Revoke { id } => revoke(&db, &id).await,
    };
    db.pool.close().await;
    result
}

async fn create_invite(db: &Db, c: Create) -> Result<String, String> {
    let code = InviteCode::generate();
    let digest = code
        .digest()
        .map_err(|_| "generated an invalid code".to_owned())?;
    let id = random_uuid();
    let now = now_ms();
    let expires_at = now.saturating_add(c.expires_in_ms);
    sqlx::query(
        "INSERT INTO registration_invites \
         (id, code_hash, bound_email, max_uses, used_count, expires_at, note, created_at) \
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7)",
    )
    .bind(&id)
    .bind(digest.to_vec())
    .bind(c.email.clone())
    .bind(c.uses)
    .bind(expires_at)
    .bind(c.note.clone())
    .bind(now)
    .execute(&db.pool)
    .await
    .map_err(db_error)?;
    let mut out = String::new();
    // The code, once. It is in no log and in no table.
    let _ = writeln!(out, "code:    {}", code.expose());
    let _ = writeln!(out, "id:      {id}");
    let _ = writeln!(
        out,
        "email:   {}",
        c.email.as_deref().unwrap_or("any (not bound)")
    );
    let _ = writeln!(out, "uses:    {}", c.uses);
    let _ = writeln!(out, "expires: {}", timestamp(expires_at));
    if let Some(note) = &c.note {
        let _ = writeln!(out, "note:    {note}");
    }
    Ok(out)
}

/// One row of `invite ls`.
#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    bound_email: Option<String>,
    max_uses: i64,
    used_count: i64,
    expires_at: Option<i64>,
    note: Option<String>,
    created_at: i64,
    revoked_at: Option<i64>,
}

async fn list(db: &Db, all: bool) -> Result<String, String> {
    let now = now_ms();
    let usable = if all {
        ""
    } else {
        " WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $1) \
         AND used_count < max_uses"
    };
    let sql = format!(
        "SELECT id, bound_email, CAST(max_uses AS BIGINT) AS max_uses, \
         CAST(used_count AS BIGINT) AS used_count, expires_at, note, created_at, revoked_at \
         FROM registration_invites{usable} ORDER BY created_at, id"
    );
    let mut query = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
    if !all {
        query = query.bind(now);
    }
    let rows = query.fetch_all(&db.pool).await.map_err(db_error)?;
    if rows.is_empty() {
        return Ok(if all {
            "No invites.\n".into()
        } else {
            "No usable invites (--all lists every invite).\n".into()
        });
    }
    let mut out = String::new();
    for row in rows {
        let state = match (row.revoked_at, row.expires_at) {
            (Some(at), _) => format!("revoked {}", timestamp(at)),
            (None, Some(at)) if at <= now => format!("expired {}", timestamp(at)),
            (None, Some(at)) => format!("expires {}", timestamp(at)),
            (None, None) => "never expires".into(),
        };
        let _ = writeln!(
            out,
            "{}  {}/{} used  {}  {}  created {}{}",
            row.id,
            row.used_count,
            row.max_uses,
            row.bound_email.as_deref().unwrap_or("any email"),
            state,
            timestamp(row.created_at),
            row.note
                .as_deref()
                .map(|n| format!("  note: {n}"))
                .unwrap_or_default(),
        );
        let uses: Vec<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT u.account_id, a.email, u.used_at FROM registration_invite_uses u \
             LEFT JOIN accounts a ON a.id = u.account_id \
             WHERE u.invite_id = $1 ORDER BY u.used_at",
        )
        .bind(&row.id)
        .fetch_all(&db.pool)
        .await
        .map_err(db_error)?;
        for (account, email, at) in uses {
            let _ = writeln!(
                out,
                "    used by {account} {} on {}",
                email.as_deref().unwrap_or("-"),
                timestamp(at)
            );
        }
    }
    Ok(out)
}

async fn revoke(db: &Db, id: &str) -> Result<String, String> {
    let done = sqlx::query(
        "UPDATE registration_invites SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
    )
    .bind(now_ms())
    .bind(id)
    .execute(&db.pool)
    .await
    .map_err(db_error)?;
    if done.rows_affected() == 1 {
        return Ok(format!(
            "Revoked invite {id}. Accounts it already created stay.\n"
        ));
    }
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM registration_invites WHERE id = $1")
            .bind(id)
            .fetch_optional(&db.pool)
            .await
            .map_err(db_error)?;
    match exists {
        Some(_) => Err(format!("invite {id} is already revoked")),
        None => Err(format!(
            "no invite with id {id} (invite ls --all lists them)"
        )),
    }
}

fn db_error(e: sqlx::Error) -> String {
    format!("database error: {e}")
}

/// A random (version 4) UUID, for an invite's `id`.
fn random_uuid() -> String {
    let mut b = random::array::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = data_encoding::HEXLOWER.encode(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Unix ms as `2026-11-25 18:04Z`.
fn timestamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Refuses to run as root on a SQLite database another user owns (ADR 0048
/// §1.4): SQLite could create its `-wal` and `-shm` files owned by root,
/// and the server, which runs as that user, could no longer write them.
fn check_sqlite_owner(url: &str) -> Result<(), String> {
    let Some(path) = db::sqlite_path(url) else {
        return Ok(());
    };
    owner_rule(running_uid(), file_uid(&path))
}

/// The rule of [`check_sqlite_owner`], given the UIDs it found.
fn owner_rule(running: Option<u32>, owner: Option<u32>) -> Result<(), String> {
    match (running, owner) {
        (Some(0), Some(owner)) if owner != 0 => Err(format!(
            "refusing to run as root on a SQLite database owned by UID {owner}: SQLite could leave \
             files the server can't write. Run it as that user instead, for example \
             `setpriv --reuid={owner} --regid={owner} --clear-groups klav-server invite …`"
        )),
        _ => Ok(()),
    }
}

/// The UID this process runs as, where it can be read without `unsafe`
/// (`/proc/self` belongs to it on Linux). `None` elsewhere.
fn running_uid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").ok().map(|m| m.uid())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(unix)]
fn file_uid(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn file_uid(_path: &std::path::Path) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn create(text: &str) -> Result<Create, String> {
        match parse(&args(text))? {
            Command::Create(c) => Ok(c),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_defaults_to_one_use_for_thirty_days() {
        let c = create("create").unwrap();
        assert_eq!(c.uses, 1);
        assert_eq!(c.expires_in_ms, 30 * DAY_MS);
        assert_eq!(c.email, None);
        let c = create("create --email  Ana@Example.COM --expires 36h --note waitlist").unwrap();
        assert_eq!(c.email.as_deref(), Some("ana@example.com"));
        assert_eq!(c.expires_in_ms, 36 * HOUR_MS);
        assert_eq!(c.note.as_deref(), Some("waitlist"));
    }

    #[test]
    fn batch_codes_need_an_expiry_of_two_weeks_and_fifty_uses_at_most() {
        assert!(create("create --uses 5").unwrap_err().contains("--expires"));
        assert_eq!(create("create --uses 50 --expires 14d").unwrap().uses, 50);
        assert!(
            create("create --uses 51 --expires 14d")
                .unwrap_err()
                .contains("50")
        );
        assert!(
            create("create --uses 2 --expires 15d")
                .unwrap_err()
                .contains("14")
        );
        assert!(create("create --uses 2 --expires 337h").is_err());
        assert!(create("create --uses 2 --expires 336h").is_ok());
        assert!(create("create --uses 2 --expires 7d --email a@b.c").is_err());
        assert!(create("create --uses 0").is_err());
        assert!(create("create --uses -3").is_err());
        assert!(create("create --expires 366d").is_err());
        for bad in ["0d", "d", "5w", "+3d", "3", "1.5d", "99999999999999999d"] {
            assert!(create(&format!("create --expires {bad}")).is_err(), "{bad}");
        }
        assert!(create("create --email not-an-email").is_err());
        assert!(create(&format!("create --note {}", "x".repeat(201))).is_err());
        assert!(create("create --bogus").is_err());
    }

    #[test]
    fn ls_and_revoke_parse() {
        assert_eq!(parse(&args("ls")).unwrap(), Command::Ls { all: false });
        assert_eq!(parse(&args("ls --all")).unwrap(), Command::Ls { all: true });
        assert!(parse(&args("ls --every")).is_err());
        assert_eq!(
            parse(&args("revoke abc")).unwrap(),
            Command::Revoke { id: "abc".into() }
        );
        assert!(parse(&args("revoke")).is_err());
        assert!(parse(&args("revoke a b")).is_err());
        assert!(parse(&args("")).is_err());
        assert!(parse(&args("delete x")).is_err());
    }

    #[test]
    fn root_on_another_users_sqlite_file_is_refused() {
        assert!(
            owner_rule(Some(0), Some(10001))
                .unwrap_err()
                .contains("10001")
        );
        assert!(owner_rule(Some(0), Some(0)).is_ok());
        assert!(owner_rule(Some(10001), Some(10001)).is_ok());
        assert!(owner_rule(Some(10001), Some(0)).is_ok());
        assert!(owner_rule(None, Some(10001)).is_ok());
        assert!(owner_rule(Some(0), None).is_ok());
    }

    #[test]
    fn timestamps_and_ids_read_well() {
        assert_eq!(timestamp(0), "1970-01-01 00:00Z");
        assert_eq!(timestamp(1_795_629_840_000), "2026-11-25 18:04Z");
        let id = random_uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_ne!(random_uuid(), id);
    }
}
