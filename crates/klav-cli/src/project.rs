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
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

/// A loaded `klav.toml`, references expanded.
#[derive(Debug, Default)]
pub(crate) struct ProjectConfig {
    /// Where it was read from (canonical).
    pub(crate) path: PathBuf,
    /// Its text as read: what [`confirm_trusted`] pins.
    text: String,
    /// `Vault/Project`, if declared.
    pub(crate) project: Option<String>,
    /// Variable → full reference.
    pub(crate) env: BTreeMap<String, String>,
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
    for (name, value) in raw.env {
        validate_env_name(&name).map_err(|e| usage(format!("{}: {e}", path.display())))?;
        let reference = config
            .expand(&value)
            .map_err(|e| usage(format!("{}: [env] {name}: {e}", path.display())))?;
        config.env.insert(name, reference);
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
    let mut pins: BTreeMap<String, String> = match std::fs::read(&pins_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    };
    let key = config.path.display().to_string();
    if pins.get(&key) == Some(&config.text) {
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
    pins.insert(key, config.text.clone());
    home.ensure()?;
    klav_client::home::write_private(
        &pins_path,
        &serde_json::to_vec_pretty(&pins).map_err(|e| usage(e.to_string()))?,
    )?;
    Ok(())
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
        Some(_) => Err(format!(
            "{value:?} is neither klav://vault/project/item/field nor item/field"
        )),
        None => Err(format!(
            "{value:?} is not a klav:// reference (short item/field references need `project` in klav.toml)"
        )),
    }
}

pub(crate) fn is_reference(value: &str) -> bool {
    value.trim().starts_with(SCHEME)
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
    fn finds_the_nearest_file_upwards() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "").unwrap();
        let deep = dir.path().join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find(&deep).unwrap(), dir.path().join(FILE_NAME));
    }
}
