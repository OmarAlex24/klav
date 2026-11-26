//! The Klav skill inside the sandbox (ADR 0036 E1.4): `klav-forward up`
//! installs the `skill/SKILL.md` it carries in `~/.claude/skills/klav/` and
//! `~/.agents/skills/klav/` when there is none, replaces an unchanged copy
//! of an older published version, and leaves anything else as it is.
//!
//! There is no record of what Klav wrote in a sandbox (ADR 0033 §3.4) and
//! nobody to ask, so the only copy it replaces is one that matches a
//! published version byte for byte.

use std::path::{Path, PathBuf};

/// The skill this binary carries (text, no vault code).
pub(crate) const SKILL: &str = include_str!("../../../skill/SKILL.md");

/// Every published `SKILL.md`, oldest first: its version and SHA-256. The
/// same list as `klav-cli`'s (a test reads it from there), and the last
/// entry is [`SKILL`].
pub(crate) const PUBLISHED: &[(&str, &str)] = &[
    (
        "0.1.0",
        "025c9c8c7a4cd45d28e0ccc0a0fd75cecaf323499d24038151593f8a62e638b9",
    ),
    (
        "0.1.0",
        "20c54afac6514691b1a5ed22b9233ebe49c9cf538b056d09c439226dea2b8062",
    ),
    (
        "0.1.0",
        "395c99cc0175d02bb724b888816bc5ae74ab98a065c5132cf65f7ab027076d8c",
    ),
    (
        "0.1.0",
        "46f3a5d4a67e2c1da5adccbb5acacfabdaeb8510188ca49958990d4a0fff88fd",
    ),
    (
        "0.1.0",
        "e2d1d9cec7ba4647e6130291e1b9e0bd6b0090f21899831fc5628f9cb71d5e05",
    ),
    (
        "0.1.0",
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
    (
        "0.3.3",
        "3c61c138f694ee4f8c0890a8d03543167764ec928751946b7a78debcf382bcac",
    ),
    (
        "0.3.4",
        "dbd927e1c787fec234e182957f71b11c01736e2883730dc6520a6013e136e3b0",
    ),
    (
        "0.3.5",
        "985c93af1f0dfe3fd912c3cde1d6859a2b560cbe5f67442347859b176cf7965f",
    ),
];

/// The skill folders of the sandbox's user, relative to its home.
pub(crate) const FOLDERS: &[&str] = &[".claude/skills/klav", ".agents/skills/klav"];

/// SHA-256 of `bytes`, lower-case hex (through `klav-core`).
pub(crate) fn sha256(bytes: &[u8]) -> String {
    klav_core::crypto::agent::request_digest(bytes)
}

/// What happened in one folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// There was none: installed.
    Installed(PathBuf),
    /// An unchanged copy of an older version: replaced.
    Updated {
        /// The file.
        path: PathBuf,
        /// The version it had.
        from: &'static str,
    },
    /// The same version: nothing to do.
    Current(PathBuf),
    /// Edited, not Klav's, or newer: left as it is.
    Left(PathBuf),
    /// Could not be read or written.
    Failed {
        /// The file.
        path: PathBuf,
        /// Why.
        error: String,
    },
}

impl Outcome {
    /// One line for `up`'s output.
    pub(crate) fn line(&self) -> String {
        match self {
            Self::Installed(p) => format!("installed the Klav skill in {}", p.display()),
            Self::Updated { path, from } => format!(
                "updated the Klav skill in {} (it was the unchanged {from})",
                path.display()
            ),
            Self::Current(p) => format!("the Klav skill in {} is current", p.display()),
            Self::Left(p) => format!(
                "did not install the Klav skill in {}: a skill is there already (edited, not Klav's, or newer), left as it is",
                p.display()
            ),
            Self::Failed { path, error } => {
                format!(
                    "could not install the Klav skill in {}: {error}",
                    path.display()
                )
            }
        }
    }
}

/// Installs or updates the skill in each of [`FOLDERS`] under `home`.
pub(crate) fn install(home: &Path) -> Vec<Outcome> {
    FOLDERS
        .iter()
        .map(|folder| install_one(&home.join(folder).join("SKILL.md"), SKILL, PUBLISHED))
        .collect()
}

/// [`install`] in one file, with `skill` as the text carried and
/// `published` as the list (tests give stand-ins).
fn install_one(path: &Path, skill: &str, published: &[(&'static str, &str)]) -> Outcome {
    let ours = sha256(skill.as_bytes());
    let found = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Outcome::Failed {
                path: path.to_owned(),
                error: e.to_string(),
            };
        }
    };
    let older = match &found {
        None => None,
        Some(bytes) => {
            let theirs = sha256(bytes);
            if theirs == ours {
                return Outcome::Current(path.to_owned());
            }
            let ours_at = published.iter().rposition(|(_, h)| *h == ours);
            match published.iter().rposition(|(_, h)| *h == theirs) {
                Some(at) if ours_at.is_some_and(|ours_at| at < ours_at) => Some(published[at].0),
                _ => return Outcome::Left(path.to_owned()),
            }
        }
    };
    if let Err(e) = write(path, skill.as_bytes()) {
        return Outcome::Failed {
            path: path.to_owned(),
            error: e.to_string(),
        };
    }
    match older {
        None => Outcome::Installed(path.to_owned()),
        Some(from) => Outcome::Updated {
            path: path.to_owned(),
            from,
        },
    }
}

/// A temporary file and `rename`, so a reader never sees half a skill.
fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".SKILL.md.tmp-{}", std::process::id()));
    // A new file only: never through a link or a file someone left there.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let synced = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    synced
        .and_then(|()| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_carried_skill_is_the_last_published_one() {
        assert_eq!(
            PUBLISHED.last().map(|(_, h)| *h),
            Some(sha256(SKILL.as_bytes()).as_str())
        );
    }

    /// The same list as `klav-cli`'s, in the same order: read from its
    /// source, since this crate may not depend on it.
    #[test]
    fn the_published_list_is_klav_clis() {
        let cli = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../klav-cli/src/skill.rs"),
        )
        .expect("klav-cli's skill.rs");
        let start = cli.find("const PUBLISHED").expect("its list");
        let end = start + cli[start..].find("];").expect("its end");
        let hashes: Vec<&str> = cli[start..end]
            .split('"')
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        assert_eq!(
            hashes,
            PUBLISHED.iter().map(|(_, h)| *h).collect::<Vec<_>>()
        );
        // The versions it names after the legacy ones, in order.
        let named: Vec<&str> = cli[start..end]
            .split('"')
            .filter(|s| {
                s.split('.').count() == 3 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            })
            .collect();
        let ours: Vec<&str> = PUBLISHED
            .iter()
            .map(|(v, _)| *v)
            .filter(|v| *v != "0.1.0")
            .collect();
        assert_eq!(named, ours);
    }

    /// The temporary file is always a new one: a link left at its name is
    /// never written through, and the install says it failed.
    #[test]
    fn a_link_at_the_temporary_name_is_never_written_through() {
        let home = crate::TestDir::new();
        let path = home.path().join(FOLDERS[0]).join("SKILL.md");
        let dir = path.parent().expect("dir");
        std::fs::create_dir_all(dir).expect("dir");
        let elsewhere = home.path().join("elsewhere");
        std::fs::write(&elsewhere, "untouched").expect("write");
        let tmp = dir.join(format!(".SKILL.md.tmp-{}", std::process::id()));
        std::os::unix::fs::symlink(&elsewhere, &tmp).expect("link");
        let out = install_one(&path, SKILL, PUBLISHED);
        assert!(matches!(out, Outcome::Failed { .. }), "{}", out.line());
        assert_eq!(
            std::fs::read_to_string(&elsewhere).expect("read"),
            "untouched"
        );
        assert!(!path.exists());
    }

    #[test]
    fn it_installs_updates_an_unchanged_older_copy_and_leaves_the_rest() {
        let home = crate::TestDir::new();
        let at = |i: usize| home.path().join(FOLDERS[i]).join("SKILL.md");
        // None in the first; an edited copy in the second.
        std::fs::create_dir_all(at(1).parent().expect("dir")).expect("dir");
        std::fs::write(at(1), "my own notes").expect("write");
        let out = install(home.path());
        assert_eq!(out[0], Outcome::Installed(at(0)));
        assert_eq!(out[1], Outcome::Left(at(1)));
        assert_eq!(
            std::fs::read_to_string(at(1)).expect("read"),
            "my own notes"
        );
        assert_eq!(std::fs::read_to_string(at(0)).expect("read"), SKILL);
        // Again: current.
        assert_eq!(install(home.path())[0], Outcome::Current(at(0)));
    }

    /// An unchanged older copy is replaced; a newer published one, an
    /// edited one and one never published are left. With a stand-in list,
    /// since the older texts are not in this repository.
    #[test]
    fn only_an_unchanged_older_published_copy_is_replaced() {
        let (old, mid, new) = ("old skill", "mid skill", "new skill");
        let list = [
            ("0.1.0", sha256(old.as_bytes())),
            ("0.2.0", sha256(mid.as_bytes())),
            ("0.3.0", sha256(new.as_bytes())),
        ];
        let published: Vec<(&'static str, &str)> =
            list.iter().map(|(v, h)| (*v, h.as_str())).collect();
        let home = crate::TestDir::new();
        let path = home.path().join("SKILL.md");
        for (there, carried, expected) in [
            (
                old,
                mid,
                Outcome::Updated {
                    path: path.clone(),
                    from: "0.1.0",
                },
            ),
            (new, mid, Outcome::Left(path.clone())),
            ("old skill, edited", mid, Outcome::Left(path.clone())),
            (mid, mid, Outcome::Current(path.clone())),
        ] {
            std::fs::write(&path, there).expect("write");
            assert_eq!(install_one(&path, carried, &published), expected, "{there}");
            let now = std::fs::read_to_string(&path).expect("read");
            let replaced = matches!(expected, Outcome::Updated { .. });
            assert_eq!(now, if replaced { carried } else { there }, "{there}");
        }
    }
}
