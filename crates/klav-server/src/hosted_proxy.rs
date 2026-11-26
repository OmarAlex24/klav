//! `klav-server hosted-proxy enable|disable|ls` (ADR 0051 §8, Q6): the
//! per-account switch for Klav Cloud's hosted proxy, against the configured
//! database, with no HTTP admin API. Whoever can read and write the
//! database already controls the server, so this adds no privilege.
//!
//! Like `klav-server invite`, these commands never migrate and run next to
//! a running server. They log nothing and add no audit event (ADR 0051 §8).
//! Turning the switch off changes only what the hosted proxy's own agents
//! read in `GET /v1/agent/me`; self-hosted proxies and every other agent
//! are untouched.

use std::fmt::Write as _;

use crate::config::Config;
use crate::db::{Db, now_ms};
use crate::invites::{check_sqlite_owner, db_error, timestamp};

/// Usage of `klav-server hosted-proxy`.
pub const USAGE: &str = "usage: klav-server hosted-proxy enable <EMAIL>
       klav-server hosted-proxy disable <EMAIL>
       klav-server hosted-proxy ls
  [--config <path>] works with every subcommand.";

/// A parsed `hosted-proxy` subcommand.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Entitle the account with this e-mail (normalized like sign-up).
    Enable {
        /// The account's e-mail.
        email: String,
    },
    /// Take the entitlement away.
    Disable {
        /// The account's e-mail.
        email: String,
    },
    /// List the entitled accounts.
    Ls,
}

/// Parses the arguments after `hosted-proxy` (without `--config`).
pub fn parse(args: &[String]) -> Result<Command, String> {
    let email = |raw: &String| {
        crate::validate::email(raw).map_err(|_| format!("{raw:?} is not a valid email address"))
    };
    match args {
        [sub, raw] if sub == "enable" => Ok(Command::Enable { email: email(raw)? }),
        [sub, raw] if sub == "disable" => Ok(Command::Disable { email: email(raw)? }),
        [sub] if sub == "ls" => Ok(Command::Ls),
        [sub, ..] if sub == "enable" || sub == "disable" => {
            Err(format!("{sub} takes one email\n{USAGE}"))
        }
        [sub, ..] if sub == "ls" => Err(format!("ls takes no arguments\n{USAGE}")),
        [other, ..] => Err(format!("unknown hosted-proxy subcommand {other}\n{USAGE}")),
        [] => Err(USAGE.to_owned()),
    }
}

/// Runs a parsed command against the configured database. `Ok` is what to
/// print on stdout; `Err` is a message for stderr.
pub async fn run(config: &Config, command: Command) -> Result<String, String> {
    check_sqlite_owner(&config.database_url)?;
    let db = Db::connect_existing(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let result = match command {
        Command::Enable { email } => switch(&db, &email, true).await,
        Command::Disable { email } => switch(&db, &email, false).await,
        Command::Ls => list(&db).await,
    };
    db.pool.close().await;
    result
}

async fn switch(db: &Db, email: &str, on: bool) -> Result<String, String> {
    // The same normalization as sign-up, whoever built the command.
    let email = &crate::validate::email(email)
        .map_err(|_| format!("{email:?} is not a valid email address"))?;
    let done = sqlx::query(
        "UPDATE accounts SET hosted_proxy = $1, hosted_proxy_at = $2 \
         WHERE email = $3 AND hosted_proxy <> $1",
    )
    .bind(i64::from(on))
    .bind(now_ms())
    .bind(email)
    .execute(&db.pool)
    .await
    .map_err(db_error)?;
    if done.rows_affected() == 0 {
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(&db.pool)
            .await
            .map_err(db_error)?;
        return match exists {
            None => Err(format!("no account with email {email}")),
            Some(_) if on => Ok(format!(
                "Klav Cloud's hosted proxy was already on for {email}.\n"
            )),
            Some(_) => Ok(format!(
                "Klav Cloud's hosted proxy was already off for {email}.\n"
            )),
        };
    }
    Ok(if on {
        format!(
            "Klav Cloud's hosted proxy is on for {email}. The person can turn it on from a device.\n"
        )
    } else {
        format!(
            "Klav Cloud's hosted proxy is off for {email}. Its hosted agents stay registered and \
             the hosted proxy stops serving the account at its next check; self-hosted proxies \
             are untouched.\n"
        )
    })
}

async fn list(db: &Db) -> Result<String, String> {
    let rows: Vec<(String, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT a.id, a.email, a.hosted_proxy_at, \
         CAST((SELECT COUNT(*) FROM agents g WHERE g.account_id = a.id AND g.hosted <> 0 \
               AND g.status <> 'revoked') AS BIGINT) AS hosted_agents \
         FROM accounts a WHERE a.hosted_proxy <> 0 ORDER BY a.hosted_proxy_at, a.email",
    )
    .fetch_all(&db.pool)
    .await
    .map_err(db_error)?;
    if rows.is_empty() {
        return Ok("No account has Klav Cloud's hosted proxy.\n".into());
    }
    let mut out = String::new();
    for (id, email, since, agents) in rows {
        let _ = writeln!(
            out,
            "{id}  {email}  on since {}  {agents} hosted agent(s)",
            since.map_or_else(|| "-".to_owned(), timestamp),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn subcommands_parse() {
        assert_eq!(
            parse(&args("enable  Ana@Example.COM")).unwrap(),
            Command::Enable {
                email: "ana@example.com".into()
            }
        );
        assert_eq!(
            parse(&args("disable ana@example.com")).unwrap(),
            Command::Disable {
                email: "ana@example.com".into()
            }
        );
        assert_eq!(parse(&args("ls")).unwrap(), Command::Ls);
        for bad in [
            "",
            "enable",
            "enable a@b.c d@e.f",
            "enable not-an-email",
            "disable",
            "ls --all",
            "on a@b.c",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
    }
}
