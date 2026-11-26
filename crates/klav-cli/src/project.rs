//! `klav.toml`: the project file of a repository (design §7). It holds
//! references, never secrets, so it can be committed.
//!
//! ```toml
//! project = "Work/acme-api"          # optional: enables short references
//!
//! [env]
//! STRIPE_KEY   = "klav://Work/acme-api/Stripe/api_key"
//! DATABASE_URL = "Postgres/url"      # short: klav://Work/acme-api/Postgres/url
//!
//! [files]
//! "secrets/AuthKey.p8" = "klav://Work/app-ios/APNs/key"
//! ```
//!
//! With environments (ADR 0032 §5), a text value of `[env]` is a variable
//! of the unnamed environment (today's), and a table is a named one that
//! adds to the vault's environment of that name; `default_env` picks one
//! for `klav run` without `--env`, and cannot sit next to text variables in
//! `[env]`:
//!
//! ```toml
//! project     = "Work/acme-api"
//! default_env = "development"
//!
//! [env.production]
//! SENTRY_DSN = "Sentry/dsn"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{CliResult, usage};

/// File name looked up from the current directory upwards.
pub(crate) const FILE_NAME: &str = "klav.toml";

/// Reads `git remote get-url <remote>` inside `cwd` and normalizes it to
/// `host/owner/repo` (ADR 0032 §2). Returns `None` if `cwd` is not a Git
/// repository, `remote` does not exist, or the URL cannot be normalized.
pub(crate) fn detect_git_repo(cwd: &Path, remote: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .arg("remote")
        .arg("get-url")
        .arg(remote)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    klav_core::model::normalize_repo_url(raw.trim()).ok()
}

const SCHEME: &str = "klav://";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    project: Option<String>,
    default_env: Option<String>,
    #[serde(default)]
    env: toml::Table,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

/// A loaded `klav.toml`, references expanded.
#[derive(Debug, Default, Clone)]
pub(crate) struct ProjectConfig {
    /// Where it was read from (canonical).
    pub(crate) path: PathBuf,
    /// Its text as read: what [`confirm_trusted`] pins.
    text: String,
    /// `Vault/Project`, if declared.
    pub(crate) project: Option<String>,
    /// Variable → full reference: the unnamed environment (`[env]`'s text
    /// values).
    pub(crate) env: BTreeMap<String, String>,
    /// `default_env`, if set (ADR 0032 §5).
    pub(crate) default_env: Option<String>,
    /// `[env.<name>]`: environment → variable → full reference.
    pub(crate) envs: BTreeMap<String, BTreeMap<String, String>>,
    /// Absolute path → full reference.
    pub(crate) files: BTreeMap<PathBuf, String>,
}

/// The nearest `klav.toml` from `start` upwards, up to the root of the git
/// repository or the home directory, whichever comes first: a `klav.toml`
/// in `/tmp` or another person's directory above does not apply.
pub(crate) fn find(start: &Path) -> Option<PathBuf> {
    find_within(
        start,
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    )
}

fn find_within(start: &Path, home: Option<&Path>) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() || home.is_some_and(|h| h == dir) {
            return None;
        }
    }
    None
}

/// Whether `target` (inside `dir`, canonical) stays inside once symbolic
/// links are followed: its nearest existing ancestor is checked, as the
/// rest does not exist yet.
fn stays_inside(dir: &Path, target: &Path) -> std::io::Result<bool> {
    let Some(existing) = target.ancestors().skip(1).find(|a| a.exists()) else {
        return Ok(false);
    };
    Ok(existing.canonicalize()?.starts_with(dir))
}

/// Loads `explicit`, or the nearest `klav.toml` (none is fine).
pub(crate) fn load(explicit: Option<&Path>) -> CliResult<Option<ProjectConfig>> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => match find(&std::env::current_dir()?) {
            Some(p) => p,
            None => return Ok(None),
        },
    };
    let text =
        std::fs::read_to_string(&path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    let raw: RawConfig =
        toml::from_str(&text).map_err(|e| usage(format!("{}: {}", path.display(), e.message())))?;
    let canonical = path.canonicalize()?;
    let dir = canonical
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let project = raw.project.map(|p| p.trim_matches('/').to_owned());
    if let Some(p) = &project
        && p.split('/').filter(|s| !s.is_empty()).count() != 2
    {
        return Err(usage(format!(
            "{}: project must be \"Vault/Project\", got {p:?}",
            path.display()
        )));
    }
    let mut config = ProjectConfig {
        path: canonical,
        text,
        project,
        ..ProjectConfig::default()
    };
    // Errors name the key, never a value: a secret pasted by mistake where
    // a reference goes must not reach the terminal (ADR 0032 §6).
    for (name, value) in raw.env {
        match value {
            toml::Value::String(text) => {
                validate_env_name(&name).map_err(|e| usage(format!("{}: {e}", path.display())))?;
                let reference = config
                    .expand(&text)
                    .map_err(|e| usage(format!("{}: [env] {name}: {e}", path.display())))?;
                config.env.insert(name, reference);
            }
            toml::Value::Table(table) => {
                klav_core::model::environment::validate_environment_name(&name).map_err(|_| {
                    usage(format!(
                        "{}: [env.{name}]: an environment is named [a-z0-9][a-z0-9_-]{{0,63}}",
                        path.display()
                    ))
                })?;
                let mut vars = BTreeMap::new();
                for (var, value) in table {
                    validate_env_name(&var)
                        .map_err(|e| usage(format!("{}: [env.{name}] {e}", path.display())))?;
                    let toml::Value::String(text) = value else {
                        return Err(usage(format!(
                            "{}: [env.{name}] {var}: expected a reference in quotes",
                            path.display()
                        )));
                    };
                    let reference = config.expand(&text).map_err(|e| {
                        usage(format!("{}: [env.{name}] {var}: {e}", path.display()))
                    })?;
                    vars.insert(var, reference);
                }
                config.envs.insert(name, vars);
            }
            _ => {
                return Err(usage(format!(
                    "{}: [env] {name}: expected a reference in quotes or a table",
                    path.display()
                )));
            }
        }
    }
    if let Some(default) = &raw.default_env {
        klav_core::model::environment::validate_environment_name(default).map_err(|_| {
            usage(format!(
                "{}: default_env: an environment is named [a-z0-9][a-z0-9_-]{{0,63}}",
                path.display()
            ))
        })?;
        if !config.env.is_empty() {
            return Err(usage(format!(
                "{}: default_env and variables in [env] at once: move them to [env.{default}]",
                path.display()
            )));
        }
        config.default_env = Some(default.clone());
    }
    for (file, value) in raw.files {
        let reference = config
            .expand(&value)
            .map_err(|e| usage(format!("{}: [files] {file:?}: {e}", path.display())))?;
        let target = Path::new(&file);
        if target.is_absolute() || target.components().any(|c| c.as_os_str() == "..") {
            return Err(usage(format!(
                "{}: [files] {file:?} must be a relative path inside the project",
                path.display()
            )));
        }
        let target = dir.join(target);
        if !stays_inside(&dir, &target)? {
            return Err(usage(format!(
                "{}: [files] {file:?} goes out of the project through a symbolic link",
                path.display()
            )));
        }
        config.files.insert(target, reference);
    }
    Ok(Some(config))
}

/// Where the `klav.toml` files the person approved are pinned, by path.
const TRUSTED_FILE: &str = "trusted-projects.json";

/// Before `klav run` uses a `klav.toml` that is new or changed since the
/// person last approved it, shows what it asks for and asks her: a
/// repository she just cloned should not be able to put any of her secrets
/// in the environment of a command it also controls. The approved text is
/// pinned in `$KLAV_HOME`, so this asks once per file and change.
pub(crate) fn confirm_trusted(
    home: &klav_client::Home,
    config: &ProjectConfig,
    yes: bool,
) -> CliResult<()> {
    use std::io::{BufRead, IsTerminal, Write};
    let pins_path = home.file(TRUSTED_FILE);
    let mut pins = read_pins(&pins_path);
    let key = config.path.display().to_string();
    if pins.get(&key).is_some_and(|p| p.text == config.text) {
        return Ok(());
    }
    if !yes {
        let known = pins.contains_key(&key);
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(usage(format!(
                "{key} is {}: run `klav run` in a terminal to review it, or pass --trust",
                if known {
                    "changed since you approved it"
                } else {
                    "new"
                }
            )));
        }
        let mut shown = format!(
            "{key} is {} and asks for:\n",
            if known { "changed" } else { "new" }
        );
        for (name, reference) in &config.env {
            shown.push_str(&format!("  env   {name} = {reference}\n"));
        }
        for (file, reference) in &config.files {
            shown.push_str(&format!("  file  {} = {reference}\n", file.display()));
        }
        eprint!("{shown}Use it? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "s" | "si" | "sí"
        ) {
            return Err(usage("cancelled"));
        }
    }
    pins.insert(
        key,
        Pin {
            text: config.text.clone(),
            environments: Vec::new(),
        },
    );
    write_pins(home, &pins_path, &pins)
}

/// One entry of [`TRUSTED_FILE`]: the approved text and the environments
/// already confirmed with it (ADR 0032 §5). Written as the bare text, as
/// before environments, while none is confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    text: String,
    environments: Vec<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(untagged)]
enum RawPin {
    Text(String),
    WithEnvironments {
        text: String,
        #[serde(default)]
        environments: Vec<String>,
    },
}

fn read_pins(path: &Path) -> BTreeMap<String, Pin> {
    let raw: BTreeMap<String, RawPin> = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    };
    raw.into_iter()
        .map(|(k, v)| {
            let pin = match v {
                RawPin::Text(text) => Pin {
                    text,
                    environments: Vec::new(),
                },
                RawPin::WithEnvironments { text, environments } => Pin { text, environments },
            };
            (k, pin)
        })
        .collect()
}

fn write_pins(
    home: &klav_client::Home,
    path: &Path,
    pins: &BTreeMap<String, Pin>,
) -> CliResult<()> {
    let raw: BTreeMap<&String, RawPin> = pins
        .iter()
        .map(|(k, p)| {
            let raw = if p.environments.is_empty() {
                RawPin::Text(p.text.clone())
            } else {
                RawPin::WithEnvironments {
                    text: p.text.clone(),
                    environments: p.environments.clone(),
                }
            };
            (k, raw)
        })
        .collect();
    home.ensure()?;
    klav_client::home::write_private(
        path,
        &serde_json::to_vec_pretty(&raw).map_err(|e| usage(e.to_string()))?,
    )?;
    Ok(())
}

/// What `klav run --env` shows before it injects an environment the first
/// time with this `klav.toml` text (ADR 0032 §5): the project, the
/// environment, the names of its variables and where each comes from, and
/// the link's warnings (§2), which never grant or skip anything.
pub(crate) struct EnvConfirmation {
    pub(crate) project: Option<String>,
    pub(crate) environment: String,
    /// Name and origin (`vault`, `klav.toml`, `vault, by reference to …`).
    pub(crate) variables: Vec<(String, String)>,
    pub(crate) warnings: Vec<String>,
}

impl EnvConfirmation {
    fn text(&self, head: &str) -> String {
        let mut shown = format!(
            "{head}\n  project      {}\n  environment  {}\n",
            self.project.as_deref().unwrap_or("(none)"),
            self.environment
        );
        for (name, origin) in &self.variables {
            shown.push_str(&format!("  env   {name}  ({origin})\n"));
        }
        for w in &self.warnings {
            shown.push_str(&format!("warning: {w}\n"));
        }
        shown
    }
}

/// [`confirm_trusted`] for an environment: asks the first time this
/// `klav.toml` text is used with `env`, and every time the text changes;
/// with no `klav.toml` (the project came from the link), every time. The
/// warnings show, and the pin is kept, the same way: the link never skips
/// the question.
pub(crate) fn confirm_environment(
    home: &klav_client::Home,
    config: Option<&ProjectConfig>,
    shown: &EnvConfirmation,
    yes: bool,
) -> CliResult<()> {
    use std::io::{BufRead, IsTerminal, Write};
    let pins_path = home.file(TRUSTED_FILE);
    let mut pins = read_pins(&pins_path);
    let key = config.map(|c| c.path.display().to_string());
    if let (Some(key), Some(config)) = (&key, config)
        && pins
            .get(key)
            .is_some_and(|p| p.text == config.text && p.environments.contains(&shown.environment))
    {
        return Ok(());
    }
    let head = match (&key, config) {
        (Some(key), Some(config)) => {
            let known = pins.get(key).is_some_and(|p| p.text == config.text);
            format!(
                "{key} {} with the environment {}:",
                if known {
                    "is used for the first time"
                } else {
                    "is new or changed, and is used"
                },
                shown.environment
            )
        }
        _ => format!(
            "No klav.toml here; the environment {} would be injected:",
            shown.environment
        ),
    };
    if !yes {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            for w in &shown.warnings {
                crate::output::warn(w);
            }
            return Err(usage(format!(
                "the environment {} is not confirmed for this klav.toml: run `klav run` in a terminal to review it, or pass --trust",
                shown.environment
            )));
        }
        eprint!("{}Use it? [y/N] ", shown.text(&head));
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "s" | "si" | "sí"
        ) {
            return Err(usage("cancelled"));
        }
    } else {
        for w in &shown.warnings {
            crate::output::warn(w);
        }
    }
    let (Some(key), Some(config)) = (key, config) else {
        return Ok(());
    };
    let pin = pins.entry(key).or_insert_with(|| Pin {
        text: config.text.clone(),
        environments: Vec::new(),
    });
    if pin.text != config.text {
        pin.text.clone_from(&config.text);
        pin.environments.clear();
    }
    if !pin.environments.contains(&shown.environment) {
        pin.environments.push(shown.environment.clone());
    }
    write_pins(home, &pins_path, &pins)
}

/// The text a migrated `klav.toml` gets (ADR 0032 §8): its flat `[env]`
/// removed and `default_env = "<env>"` set, everything else kept as it is.
pub(crate) fn migrated_text(text: &str, env: &str) -> CliResult<String> {
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|_| usage("klav.toml does not parse"))?;
    if let Some(table) = doc
        .get_mut("env")
        .and_then(toml_edit::Item::as_table_like_mut)
    {
        let flat: Vec<String> = table
            .iter()
            .filter(|(_, v)| v.is_str())
            .map(|(k, _)| k.to_owned())
            .collect();
        for key in flat {
            table.remove(&key);
        }
        if table.is_empty() {
            doc.remove("env");
        }
    }
    doc["default_env"] = toml_edit::value(env);
    Ok(doc.to_string())
}

impl ProjectConfig {
    /// A full reference, or a short `item/field` inside `project`.
    pub(crate) fn expand(&self, value: &str) -> Result<String, String> {
        expand(self.project.as_deref(), value)
    }

    /// `project` as `(vault, project)`: agents only see that project when
    /// it is set (ADR 0014 §10).
    pub(crate) fn project_scope(&self) -> Option<(String, String)> {
        let (vault, project) = self.project.as_deref()?.split_once('/')?;
        Some((vault.to_owned(), project.to_owned()))
    }
}

/// Expands `item/field` to `klav://<project>/item/field`; full references
/// pass through.
pub(crate) fn expand(project: Option<&str>, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.starts_with(SCHEME) {
        return Ok(value.to_owned());
    }
    match project {
        Some(p) if value.split('/').count() == 2 && !value.starts_with('/') => {
            Ok(format!("{SCHEME}{p}/{value}"))
        }
        // The value is never repeated: it may be a secret put here by
        // mistake.
        Some(_) => Err("expected klav://vault/project/item/field or item/field".to_owned()),
        None => Err(
            "expected a klav:// reference (short item/field references need `project` in klav.toml)"
                .to_owned(),
        ),
    }
}

pub(crate) fn is_reference(value: &str) -> bool {
    value.trim().starts_with(SCHEME)
}

/// Whether picking the environment without `--env` (ADR 0032 §5) needs the
/// names of the project's environments in the vault: only when `klav.toml`
/// has neither `default_env` nor a flat `[env]`.
pub(crate) fn default_needs_vault(config: Option<&ProjectConfig>) -> bool {
    config.is_some_and(|c| c.default_env.is_none() && c.env.is_empty())
}

/// The environment to use without `--env` (ADR 0032 §5, answer 8), the same
/// for `klav run`, `klav agent run` and `run_with_secrets`: (1)
/// `default_env`; (2) with text variables in `[env]`, none (today's
/// behavior, no environment item read); (3) the only one among `vault` (the
/// project's environments) and the `[env.<name>]` tables; (4) with several,
/// an error that lists them. It never picks one by its name.
pub(crate) fn default_environment(
    config: Option<&ProjectConfig>,
    vault: &[String],
) -> Result<Option<String>, String> {
    let Some(config) = config else {
        return Ok(None);
    };
    if let Some(default) = &config.default_env {
        return Ok(Some(default.clone()));
    }
    if !config.env.is_empty() {
        return Ok(None);
    }
    let mut names: Vec<String> = config.envs.keys().cloned().collect();
    for name in vault {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names.sort();
    match names.len() {
        0 => Ok(None),
        1 => Ok(names.pop()),
        _ => Err(format!("there are {}: use --env", and_list(&names))),
    }
}

/// `a, b and c`.
pub(crate) fn and_list(names: &[String]) -> String {
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

/// The error for an environment neither the vault nor `klav.toml` has,
/// listing the ones that exist.
pub(crate) fn no_such_environment(
    name: &str,
    config: Option<&ProjectConfig>,
    vault: &[String],
) -> String {
    let mut known: Vec<String> = config
        .map(|c| c.envs.keys().cloned().collect())
        .unwrap_or_default();
    for n in vault {
        if !known.contains(n) {
            known.push(n.clone());
        }
    }
    known.sort();
    if known.is_empty() {
        format!("no environment {name:?} in the vault or klav.toml")
    } else {
        format!("no environment {name:?}: there are {}", and_list(&known))
    }
}

fn validate_env_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid variable name {name:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_references_need_a_project() {
        assert_eq!(
            expand(Some("Work/api"), "Stripe/api_key").unwrap(),
            "klav://Work/api/Stripe/api_key"
        );
        assert_eq!(expand(None, "klav://A/B/C/d").unwrap(), "klav://A/B/C/d");
        assert!(expand(None, "Stripe/api_key").is_err());
        assert!(expand(Some("Work/api"), "just-a-word").is_err());
        assert!(expand(Some("Work/api"), "a/b/c").is_err());
    }

    #[test]
    fn loads_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(
            &path,
            "project = \"Work/api\"\n[env]\nKEY = \"Stripe/api_key\"\n[files]\n\"s/key.p8\" = \"klav://Work/ios/APNs/key\"\n",
        )
        .unwrap();
        let config = load(Some(&path)).unwrap().unwrap();
        assert_eq!(config.env["KEY"], "klav://Work/api/Stripe/api_key");
        let (file, reference) = config.files.iter().next().unwrap();
        assert!(file.ends_with("s/key.p8"));
        assert_eq!(reference, "klav://Work/ios/APNs/key");

        for bad in [
            "[env]\n\"1BAD\" = \"klav://a/b/c/d\"\n",
            "[files]\n\"../out\" = \"klav://a/b/c/d\"\n",
            "[files]\n\"/etc/x\" = \"klav://a/b/c/d\"\n",
            "project = \"only-one\"\n",
            "secret = \"x\"\n",
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(load(Some(&path)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_search_stops_at_the_repository_or_home() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "").unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("src")).unwrap();
        assert_eq!(find_within(&repo.join("src"), None), None);
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("work")).unwrap();
        assert_eq!(find_within(&home.join("work"), Some(&home)), None);
        std::fs::write(repo.join(FILE_NAME), "").unwrap();
        assert_eq!(
            find_within(&repo.join("src"), None),
            Some(repo.join(FILE_NAME))
        );
    }

    #[test]
    fn files_cannot_leave_the_project_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("out")).unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, "[files]\n\"out/key.p8\" = \"klav://a/b/c/d\"\n").unwrap();
        assert!(load(Some(&path)).is_err());
        std::fs::write(&path, "[files]\n\"new/dir/key.p8\" = \"klav://a/b/c/d\"\n").unwrap();
        assert!(load(Some(&path)).is_ok());
    }

    #[test]
    fn the_default_environment_follows_the_order_and_never_guesses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let load_text = |text: &str| {
            std::fs::write(&path, text).unwrap();
            load(Some(&path)).unwrap().unwrap()
        };
        let vault = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        // No klav.toml: no environment.
        assert_eq!(
            default_environment(None, &vault(&["development"])),
            Ok(None)
        );
        // default_env wins, without looking at the vault.
        let c = load_text("project = \"W/P\"\ndefault_env = \"staging\"\n");
        assert!(!default_needs_vault(Some(&c)));
        assert_eq!(
            default_environment(Some(&c), &vault(&["development", "production"])),
            Ok(Some("staging".into()))
        );
        // A flat [env]: today's behavior.
        let c = load_text("project = \"W/P\"\n[env]\nA = \"klav://a/b/c/d\"\n");
        assert!(!default_needs_vault(Some(&c)));
        assert_eq!(
            default_environment(Some(&c), &vault(&["production"])),
            Ok(None)
        );
        // The only one, from the vault or klav.toml.
        let c = load_text("project = \"W/P\"\n");
        assert!(default_needs_vault(Some(&c)));
        assert_eq!(
            default_environment(Some(&c), &vault(&["production"])),
            Ok(Some("production".into()))
        );
        let c = load_text("project = \"W/P\"\n[env.development]\nA = \"klav://a/b/c/d\"\n");
        assert_eq!(
            default_environment(Some(&c), &vault(&["development"])),
            Ok(Some("development".into()))
        );
        // Several: an error listing them; `development` is never guessed.
        let e = default_environment(Some(&c), &vault(&["production", "staging"])).unwrap_err();
        assert_eq!(
            e,
            "there are development, production and staging: use --env"
        );
        assert_eq!(
            no_such_environment("qa", Some(&c), &vault(&["production"])),
            "no environment \"qa\": there are development and production"
        );
    }

    #[test]
    fn environments_in_klav_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(
            &path,
            "project = \"Work/api\"\ndefault_env = \"development\"\n[env.production]\nSENTRY_DSN = \"Sentry/dsn\"\n[env.development]\nFLAG = \"klav://W/P/Flags/dev\"\n",
        )
        .unwrap();
        let config = load(Some(&path)).unwrap().unwrap();
        assert_eq!(config.default_env.as_deref(), Some("development"));
        assert!(config.env.is_empty());
        assert_eq!(
            config.envs["production"]["SENTRY_DSN"],
            "klav://Work/api/Sentry/dsn"
        );
        assert_eq!(config.envs["development"]["FLAG"], "klav://W/P/Flags/dev");

        // Two default environments: an error that says where to move them.
        std::fs::write(
            &path,
            "default_env = \"development\"\n[env]\nA = \"klav://a/b/c/d\"\n",
        )
        .unwrap();
        let e = load(Some(&path)).unwrap_err().message().unwrap_or_default();
        assert!(e.contains("move them to [env.development]"), "{e}");

        // Errors never repeat a value: a secret pasted where a reference
        // goes stays off the terminal.
        let secret = "sk_live_NEVER_SHOWN";
        for text in [
            format!("project = \"W/P\"\n[env]\nKEY = \"{secret}\"\n"),
            format!("[env]\nKEY = \"{secret}\"\n"),
            format!("project = \"W/P\"\n[env.prod]\nKEY = \"{secret}\"\n"),
            "[env.Bad_Name]\nKEY = \"klav://a/b/c/d\"\n".to_owned(),
            "[env]\nKEY = 3\n".to_owned(),
        ] {
            std::fs::write(&path, &text).unwrap();
            let e = load(Some(&path)).unwrap_err().message().unwrap_or_default();
            assert!(!e.contains(secret), "{e}");
        }
    }

    #[test]
    fn pins_keep_the_old_format_until_an_environment_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let home = klav_client::Home::at(dir.path().join("home"));
        let path = home.file(TRUSTED_FILE);
        std::fs::create_dir_all(home.dir()).unwrap();
        // A file written before environments: path → text.
        std::fs::write(&path, r#"{"/repo/klav.toml": "project = 1"}"#).unwrap();
        let pins = read_pins(&path);
        assert_eq!(pins["/repo/klav.toml"].text, "project = 1");
        write_pins(&home, &path, &pins).unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["/repo/klav.toml"], "project = 1");

        let toml = dir.path().join(FILE_NAME);
        std::fs::write(&toml, "project = \"W/P\"\n").unwrap();
        let config = load(Some(&toml)).unwrap().unwrap();
        let shown = EnvConfirmation {
            project: Some("W/P".into()),
            environment: "development".into(),
            variables: vec![("A".into(), "vault".into())],
            warnings: Vec::new(),
        };
        confirm_environment(&home, Some(&config), &shown, true).unwrap();
        let pins = read_pins(&path);
        let pin = &pins[&config.path.display().to_string()];
        assert_eq!(pin.environments, vec!["development".to_owned()]);
        // The plain pin of the same text holds too.
        confirm_trusted(&home, &config, false).unwrap();
    }

    #[test]
    fn the_migration_keeps_the_rest_of_the_file() {
        let text = "# repo\nproject = \"W/P\"\n\n[env]\nA = \"x/y\" # a\n\n[env.prod]\nB = \"x/z\"\n\n[files]\n\"k.p8\" = \"APNs/key\"\n";
        let out = migrated_text(text, "development").unwrap();
        assert!(out.contains("# repo"));
        assert!(out.contains("default_env = \"development\""));
        assert!(!out.contains("A = "));
        assert!(out.contains("[env.prod]") && out.contains("B = \"x/z\""));
        assert!(out.contains("[files]"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, &out).unwrap();
        let config = load(Some(&path)).unwrap().unwrap();
        assert_eq!(config.default_env.as_deref(), Some("development"));
    }

    #[test]
    fn finds_the_nearest_file_upwards() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "").unwrap();
        let deep = dir.path().join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find(&deep).unwrap(), dir.path().join(FILE_NAME));
    }
}
