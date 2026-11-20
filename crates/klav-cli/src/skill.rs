//! The Klav skill (ADR 0033 §6, E3): `skill/SKILL.md` built into the
//! binary, its version, and the copies Klav installs in the skill folders of
//! agent clients.
//!
//! Klav owns a copy only while it is exactly what Klav wrote (the SHA-256 in
//! `clients.json`): an edited copy is never overwritten, a removed one is
//! never put back by itself, and a copy Klav did not write is only adopted
//! or replaced when asked.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::clients::files::{self, Target};
use crate::clients::registry::Registry;
use crate::error::{CliError, CliResult};

/// The skill this binary installs.
pub(crate) const SKILL: &str = include_str!("../../../skill/SKILL.md");

/// Name of the skill, and of its folder.
pub(crate) const NAME: &str = "klav";
/// File name inside the skill folder.
pub(crate) const FILE: &str = "SKILL.md";

/// Version of the skills Klav published before `metadata.klav-skill-version`
/// existed.
const LEGACY_VERSION: &str = "0.1.0";

/// Every skill Klav published as `name: klav`, oldest first: its version and
/// the SHA-256 of `SKILL.md`. A copy identical to one of these can be
/// adopted. The last entry is the one in this binary: changing
/// `skill/SKILL.md` needs a new version and a new line here (a test checks
/// it), so a copy is never "older" or "newer" by accident.
const PUBLISHED: &[(&str, &str)] = &[
    (
        LEGACY_VERSION,
        "025c9c8c7a4cd45d28e0ccc0a0fd75cecaf323499d24038151593f8a62e638b9",
    ),
    (
        LEGACY_VERSION,
        "20c54afac6514691b1a5ed22b9233ebe49c9cf538b056d09c439226dea2b8062",
    ),
    (
        LEGACY_VERSION,
        "395c99cc0175d02bb724b888816bc5ae74ab98a065c5132cf65f7ab027076d8c",
    ),
    (
        LEGACY_VERSION,
        "46f3a5d4a67e2c1da5adccbb5acacfabdaeb8510188ca49958990d4a0fff88fd",
    ),
    (
        LEGACY_VERSION,
        "e2d1d9cec7ba4647e6130291e1b9e0bd6b0090f21899831fc5628f9cb71d5e05",
    ),
    (
        LEGACY_VERSION,
        "e29d023e634dc43a53c9566a3963a6a3650af186d713f81722d51483a0d90b76",
    ),
    (
        "0.2.0",
        "3a0a1289d31f98317c96acefe623ca26222da8b2bc5539fef3a6ad2f812c82c6",
    ),
    (
        "0.3.0",
        "170327aa72a1b9c36df2b16577760a8cd58c7396bbc6c51a86a781d4ac1dfb81",
    ),
    (
        "0.3.1",
        "8869b935abd0f25254a4df4d8cc9888da5d3524483daaf705eddeba57070e8ff",
    ),
    (
        "0.3.2",
        "2fb998af8add332548313ce904a33e00a9b49bf99dae8666f9db0c3b37ca0962",
    ),
];

/// SHA-256 of `bytes`, lowercase hex.
pub(crate) fn sha256(bytes: &[u8]) -> String {
    klav_core::crypto::agent::request_digest(bytes)
}

/// The version of the built-in skill (`metadata.klav-skill-version`).
pub(crate) fn version() -> &'static str {
    frontmatter_version(SKILL).unwrap_or(LEGACY_VERSION)
}

/// SHA-256 of the built-in skill.
pub(crate) fn bundled_sha256() -> String {
    sha256(SKILL.as_bytes())
}

/// The published version a skill with this SHA-256 was, if any.
pub(crate) fn published_version(sha: &str) -> Option<&'static str> {
    PUBLISHED
        .iter()
        .rev()
        .find(|(_, h)| *h == sha)
        .map(|(v, _)| *v)
}

/// `metadata.klav-skill-version` of a `SKILL.md`, read from its
/// frontmatter (only the two lines it needs, no YAML parser).
pub(crate) fn frontmatter_version(text: &str) -> Option<&str> {
    let body = frontmatter(text)?;
    let mut in_metadata = false;
    for line in body.lines() {
        if line.trim_end() == "metadata:" {
            in_metadata = true;
            continue;
        }
        if in_metadata {
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_metadata = false;
                continue;
            }
            if let Some(value) = line.trim().strip_prefix("klav-skill-version:") {
                return Some(value.trim().trim_matches('"').trim_matches('\''));
            }
        }
    }
    None
}

/// `name` of a `SKILL.md`, from its frontmatter.
#[cfg(test)]
pub(crate) fn frontmatter_name(text: &str) -> Option<&str> {
    frontmatter(text)?.lines().find_map(|line| {
        line.strip_prefix("name:")
            .map(|v| v.trim().trim_matches('"').trim_matches('\''))
    })
}

fn frontmatter(text: &str) -> Option<&str> {
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))?;
    let end = rest.find("\n---")?;
    Some(&rest[..end])
}

/// Orders two dotted versions (`0.2.0`), numerically by part; a part that
/// is not a number counts as 0.
pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    let (a, b) = (parts(a), parts(b));
    let len = a.len().max(b.len());
    for i in 0..len {
        let ord = a
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&b.get(i).copied().unwrap_or(0));
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

/// `<skills dir>/klav/SKILL.md`.
pub(crate) fn file_in(skills_dir: &Path) -> PathBuf {
    skills_dir.join(NAME).join(FILE)
}

/// What a skill copy on disk is, compared with what Klav wrote there and
/// with the skill in this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CopyState {
    /// Klav's, unchanged, the same version as this binary's.
    Current,
    /// Klav's, unchanged, older than this binary's: `klav skill update`
    /// replaces it.
    Older,
    /// Klav's, unchanged, newer than this binary's (an older Klav runs
    /// now): left alone.
    Newer,
    /// Klav wrote it and someone changed it since: never overwritten.
    Edited,
    /// Klav wrote it and the person removed it: never put back by itself.
    Removed,
    /// A copy Klav did not write (or does not remember writing).
    Unmanaged,
}

/// A skill copy on disk, or one Klav wrote that is gone.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SkillCopy {
    /// `…/klav/SKILL.md`.
    pub(crate) path: PathBuf,
    pub(crate) state: CopyState,
    /// Its `metadata.klav-skill-version`, else the published skill its
    /// content is, else what Klav recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    /// SHA-256 of the copy on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sha256: Option<String>,
    /// A copy Klav did not write that is exactly a skill Klav published:
    /// `klav skill install --adopt` takes it as Klav's.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) adoptable: bool,
    /// The version the person kept their edited copy over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kept_mine: Option<String>,
}

/// What is at `path` (`<skills dir>/klav/SKILL.md`), compared with
/// `clients.json` and this binary's skill; `None` if there is nothing and
/// Klav never wrote one there.
pub(crate) fn inspect(path: &Path, registry: &Registry) -> Option<SkillCopy> {
    let record = registry.skill(path);
    let bytes = std::fs::read(path).ok();
    let sha = bytes.as_deref().map(sha256);
    let file_version = bytes.as_deref().and_then(|b| {
        let text = String::from_utf8_lossy(b);
        frontmatter_version(&text).map(str::to_owned).or_else(|| {
            sha.as_deref()
                .and_then(published_version)
                .map(str::to_owned)
        })
    });
    let state = match (&sha, record) {
        (None, None) => return None,
        (None, Some(_)) => CopyState::Removed,
        (Some(_), None) => CopyState::Unmanaged,
        (Some(sha), Some(_)) if *sha == bundled_sha256() => CopyState::Current,
        (Some(sha), Some(r)) if *sha == r.sha256 => match compare_versions(&r.version, version()) {
            std::cmp::Ordering::Less => CopyState::Older,
            std::cmp::Ordering::Equal => CopyState::Current,
            std::cmp::Ordering::Greater => CopyState::Newer,
        },
        (Some(_), Some(_)) => CopyState::Edited,
    };
    Some(SkillCopy {
        path: path.to_path_buf(),
        state,
        version: file_version.or_else(|| record.map(|r| r.version.clone())),
        adoptable: state == CopyState::Unmanaged
            && sha.as_deref().and_then(published_version).is_some(),
        sha256: sha,
        kept_mine: record.and_then(|r| r.kept_mine.clone()),
    })
}

/// Writes this binary's skill at `path` (following a link to the file it
/// points at, never replacing the link) and records it as Klav's.
pub(crate) fn write(path: &Path, registry: &mut Registry) -> CliResult<()> {
    let target = Target::resolve(path)?;
    if let Some(dir) = target.real.parent() {
        std::fs::create_dir_all(dir)?;
    }
    files::write_atomic(&target.real, SKILL.as_bytes(), 0o644)?;
    registry.wrote_skill(path, bundled_sha256(), version());
    Ok(())
}

/// Removes the copy at `path` (a link itself, not what it points at), its
/// `klav` folder if that leaves it empty, and the record.
pub(crate) fn remove(path: &Path, registry: &mut Registry) -> CliResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CliError::Other(format!("{}: {e}", path.display()))),
    }
    if let Some(dir) = path.parent() {
        // Fails, as it should, when the folder holds anything else.
        let _ = std::fs::remove_dir(dir);
    }
    registry.forget_skill(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_skill_is_the_last_published_one() {
        let (published, sha) = PUBLISHED.last().expect("published");
        assert_eq!(
            bundled_sha256(),
            *sha,
            "skill/SKILL.md changed: give it a new metadata.klav-skill-version and add its SHA-256 to PUBLISHED"
        );
        assert_eq!(version(), *published);
        assert_eq!(frontmatter_name(SKILL), Some(NAME));
    }

    #[test]
    fn published_versions_only_grow() {
        for pair in PUBLISHED.windows(2) {
            assert_ne!(
                compare_versions(pair[0].0, pair[1].0),
                std::cmp::Ordering::Greater,
                "{pair:?}"
            );
        }
        // Each content is listed once.
        let mut hashes: Vec<&str> = PUBLISHED.iter().map(|(_, h)| *h).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), PUBLISHED.len());
    }

    #[test]
    fn versions_compare_by_number() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_versions("0.2.0", "0.10.0"), Less);
        assert_eq!(compare_versions("1.0", "1.0.0"), Equal);
        assert_eq!(compare_versions("0.3.1", "0.3.0"), Greater);
    }

    #[test]
    fn frontmatter_fields_are_read_without_yaml() {
        let text = "---\nname: klav\ndescription: x\nmetadata:\n  klav-skill-version: \"0.9.1\"\n---\n# Klav\nmetadata:\n  klav-skill-version: \"9\"\n";
        assert_eq!(frontmatter_version(text), Some("0.9.1"));
        assert_eq!(frontmatter_name(text), Some("klav"));
        assert_eq!(frontmatter_version("# no frontmatter"), None);
        assert_eq!(
            frontmatter_version("---\nname: klav\n---\nmetadata:\n  klav-skill-version: 3\n"),
            None
        );
    }

    /// What left the skill for the thin one (ADR 0033 E3.2) is said where
    /// the agent meets it: in the tools' descriptions.
    #[test]
    fn what_left_the_skill_is_in_the_tools() {
        let tools = crate::mcp::tools();
        let description = |name: &str| -> String {
            tools
                .as_array()
                .expect("tools")
                .iter()
                .find(|t| t["name"] == name)
                .and_then(|t| t["description"].as_str())
                .unwrap_or_else(|| panic!("no tool {name}"))
                .to_owned()
        };
        for (tool, said) in [
            ("fill_login", "Open the login page first"),
            ("fill_login", "do not pick other selectors"),
            ("fill_login", "url_after"),
            ("run_with_secrets", "do not try to recover them"),
            ("inject_file", "ttl_seconds"),
            ("inject_file", "Never cat"),
            ("inject_file", ".gitignore"),
            ("get_totp", "seed is never injected"),
            ("create_item", "Titles are unique"),
            ("update_item", "never create a copy"),
            ("rotate_password", "never leave a change open"),
        ] {
            assert!(description(tool).contains(said), "{tool}: {said}");
        }
    }

    /// Every tool the skill names (a backticked lowercase word) exists in
    /// `klav mcp`'s `tools/list`, so the thin skill never points at a tool
    /// that is gone (ADR 0033 E3.2). Other backticked words must be listed
    /// here on purpose.
    #[test]
    fn every_tool_the_skill_names_exists() {
        const NOT_TOOLS: &[&str] = &[
            "allow",
            "ask",
            "deny",
            "warning",
            "next",
            "run_in_background",
            // The program, and client names in «If you are not connected
            // to Klav yet».
            "klav",
            "codex",
            "cursor",
            "vscode",
            // «Sandboxes» (ADR 0036 E1.2): permissions, and the fields of
            // a `klav-forward` error.
            "inject",
            "error",
            "message",
            // An error code of `klav-forward up`.
            "klav_forward_already_claimed",
        ];
        let tools = crate::mcp::tools();
        let names: Vec<&str> = tools
            .as_array()
            .expect("tools")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        let mut named = Vec::new();
        for (i, span) in SKILL.split('`').enumerate() {
            if i % 2 == 1
                && !span.is_empty()
                && span.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                named.push(span);
            }
        }
        assert!(named.contains(&"search_items"), "{named:?}");
        for word in named {
            assert!(
                names.contains(&word) || NOT_TOOLS.contains(&word),
                "the skill names `{word}`, which is not a tool of klav mcp (add it to NOT_TOOLS if it is not meant as one)"
            );
        }
    }

    /// Every `klav sandbox <command>` the skill names exists in `klav
    /// sandbox --help` (ADR 0036 E1.5). `klav-forward`'s are checked in
    /// that crate, which carries the same skill.
    #[test]
    fn every_sandbox_command_the_skill_names_exists() {
        use clap::CommandFactory;
        let cli = crate::cli::Cli::command();
        let sandbox = cli
            .find_subcommand("sandbox")
            .expect("`klav sandbox` exists");
        let mut named = Vec::new();
        for (i, span) in SKILL.split('`').enumerate() {
            if i % 2 == 1
                && let Some(rest) = span.strip_prefix("klav sandbox ")
            {
                named.push(
                    rest.split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
        }
        assert!(named.iter().any(|n| n == "start"), "{named:?}");
        for name in named {
            assert!(
                sandbox.find_subcommand(&name).is_some(),
                "the skill names `klav sandbox {name}`, which `klav sandbox --help` does not have"
            );
        }
    }
}
