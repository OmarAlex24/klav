//! `generate`.

use klav_client::Home;
use klav_client::ops::SecretText;
use klav_core::generator::{
    Generated, GeneratorKind, GeneratorOptions, RulesFallback, RulesSource, SiteHints, Strength,
    generate,
};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, Request};
use secrecy::ExposeSecret;

use crate::cli::{GenerateArgs, GeneratorTypeArg};
use crate::error::{CliError, CliResult};
use crate::output;

fn kind(args: &GenerateArgs) -> GeneratorKind {
    match args.kind {
        Some(GeneratorTypeArg::Smart) => GeneratorKind::Smart,
        Some(GeneratorTypeArg::Random) => GeneratorKind::Random,
        Some(GeneratorTypeArg::Memorable) => GeneratorKind::Memorable,
        Some(GeneratorTypeArg::Pin) => GeneratorKind::Pin,
        None if args.words.is_some() => GeneratorKind::Memorable,
        None => GeneratorKind::Smart,
    }
}

pub(crate) fn options(args: &GenerateArgs) -> GeneratorOptions {
    let defaults = GeneratorOptions::default();
    GeneratorOptions {
        kind: kind(args),
        length: args.length,
        uppercase: !args.no_uppercase,
        digits: !args.no_digits,
        symbols: !args.no_symbols,
        avoid_ambiguous: args.avoid_ambiguous,
        words: args.words.unwrap_or(defaults.words),
        separator: args.separator.clone(),
        capitalize: !args.no_capitalize,
        include_number: !args.no_number,
        pin_length: args.pin_length,
        ..defaults
    }
}

/// The site's host, from a host or a URL.
pub(crate) fn host_of(site: &str) -> Option<String> {
    klav_core::site::item_host(site)
}

fn strength_name(s: Strength) -> &'static str {
    match s {
        Strength::Weak => "weak",
        Strength::Fair => "fair",
        Strength::Strong => "strong",
        Strength::VeryStrong => "very strong",
    }
}

/// One line about the result, for stderr: never the value.
pub(crate) fn describe(g: &Generated) -> String {
    let mut out = format!("(~{:.0} bits, {})", g.bits, strength_name(g.strength));
    match &g.rules {
        Some(RulesSource::Field) => out.push_str(" following --rules"),
        Some(RulesSource::Bundled { domain }) => {
            out.push_str(&format!(" following the rules of {domain}"));
        }
        Some(RulesSource::Lengths) | None => {}
    }
    if g.limited {
        out.push_str("; the site does not allow a stronger one");
    }
    match g.fallback {
        Some(RulesFallback::Unreadable) => {
            out.push_str("; the site's rules could not be read, so this is a random password");
        }
        Some(RulesFallback::Impossible) => {
            out.push_str("; no password fits the site's rules, so this is a random password");
        }
        None => {}
    }
    out
}

pub(crate) async fn generate_cmd(args: GenerateArgs, no_daemon: bool) -> CliResult<()> {
    // Refused with any type: a separator the generator never uses for
    // this one is still a mistake to point out.
    klav_core::generator::check_separator(&args.separator)
        .map_err(|e| CliError::Usage(format!("--separator {:?}: {e}", args.separator)))?;
    let site = SiteHints {
        host: args.site.as_deref().and_then(host_of),
        password_rules: args.rules.clone(),
        ..SiteHints::default()
    };
    let generated = generate(&options(&args), &site).map_err(|e| CliError::Usage(e.to_string()))?;
    // Kept before it is shown, so that it is never lost (ADR 0022 §2).
    let note = if args.no_history {
        None
    } else if no_daemon {
        Some("not kept in the generator history (--no-daemon)".to_owned())
    } else {
        record(generated.value.expose_secret(), site.host.as_deref()).await
    };
    output::line(generated.value.expose_secret());
    output::info(&describe(&generated));
    if let Some(note) = note {
        output::info(&note);
    }
    Ok(())
}

/// Records the password in the generator history through `klavd`. Without
/// a running, unlocked daemon it is not kept: the reason comes back.
async fn record(value: &str, host: Option<&str>) -> Option<String> {
    let home = match Home::from_env() {
        Ok(home) => home,
        Err(_) => return Some("not kept in the generator history (no Klav home)".to_owned()),
    };
    let Some(mut client) = DaemonClient::connect(&home).await else {
        return Some("not kept in the generator history: klavd is not running".to_owned());
    };
    match client.call::<DaemonStatus>(Request::Status).await {
        Ok((status, _)) if status.unlocked => {}
        Ok(_) => return Some("not kept in the generator history: klavd is locked".to_owned()),
        Err(e) => return Some(format!("not kept in the generator history: {}", e.message)),
    }
    let request = Request::GeneratorRecord {
        value: SecretText::new(value),
        host: host.map(str::to_owned),
    };
    match client.call::<serde_json::Value>(request).await {
        Ok(_) => None,
        Err(e) => Some(format!("not kept in the generator history: {}", e.message)),
    }
}
