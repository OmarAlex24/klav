//! `klav skill status | install | update | uninstall | show` (ADR 0033 §6,
//! E3): the skill this `klav` carries and its copies in the clients' skill
//! folders. A copy is Klav's only while it is what Klav wrote: edited
//! copies are never overwritten and removed ones are never put back by
//! themselves.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;

use crate::cli::{
    JsonFlag, SkillCommand, SkillInstallArgs, SkillUninstallArgs, SkillUpdateArgs, SkillWhere,
};
use crate::clients::registry::Registry;
use crate::clients::{self, ALL, ClientId, Env};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::skill::{self, CopyState, SkillCopy};

pub(crate) fn skill_cmd(ctx: &mut Ctx, cmd: SkillCommand) -> CliResult<()> {
    match cmd {
        SkillCommand::Status(flag) => status(ctx, &flag),
        SkillCommand::Install(args) => install(ctx, &args),
        SkillCommand::Update(args) => update(ctx, &args),
        SkillCommand::Uninstall(args) => uninstall(ctx, &args),
        SkillCommand::Show => {
            print!("{}", skill::SKILL);
            Ok(())
        }
    }
}

/// The clients that read the skill in `skills_dir`.
fn readers(skills_dir: &Path, env: &Env) -> Vec<ClientId> {
    ALL.into_iter()
        .filter(|c| c.skills_dir(env).as_deref() == Some(skills_dir))
        .collect()
}

/// The `skills` folder of a `…/klav/SKILL.md`.
fn skills_dir_of(path: &Path) -> Option<&Path> {
    path.parent()?.parent()
}

#[derive(Serialize)]
struct CopyView {
    #[serde(flatten)]
    copy: SkillCopy,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    clients: Vec<ClientId>,
}

/// Every copy Klav knows of: in the known folders and wherever Klav wrote
/// one.
fn all_copies(env: &Env, registry: &Registry) -> Vec<CopyView> {
    let mut paths: Vec<PathBuf> = clients::known_skill_dirs(env)
        .iter()
        .map(|d| skill::file_in(d))
        .collect();
    for record in &registry.skills {
        if !paths.contains(&record.path) {
            paths.push(record.path.clone());
        }
    }
    paths
        .iter()
        .filter_map(|p| skill::inspect(p, registry))
        .map(|copy| CopyView {
            clients: skills_dir_of(&copy.path)
                .map(|d| readers(d, env))
                .unwrap_or_default(),
            copy,
        })
        .collect()
}

fn state_text(state: CopyState) -> &'static str {
    match state {
        CopyState::Current => "up to date",
        CopyState::Older => "older",
        CopyState::Newer => "newer than this klav's",
        CopyState::Edited => "edited",
        CopyState::Removed => "removed",
        CopyState::Unmanaged => "not Klav's",
    }
}

fn status(ctx: &Ctx, flag: &JsonFlag) -> CliResult<()> {
    let env = Env::from_env()?;
    let registry = Registry::load(&ctx.home)?;
    let copies = all_copies(&env, &registry);
    if flag.json {
        return output::json(&json!({
            "bundled": { "version": skill::version(), "sha256": skill::bundled_sha256() },
            "copies": copies,
        }));
    }
    output::info(&format!(
        "This klav carries the Klav skill {}.",
        skill::version()
    ));
    if copies.is_empty() {
        output::info(
            "No copy of it is installed: `klav skill install` puts one in the folders of the clients installed here.",
        );
        return Ok(());
    }
    output::table(
        &["COPY", "STATE", "VERSION", "CLIENTS"],
        &copies
            .iter()
            .map(|c| {
                vec![
                    c.copy.path.display().to_string(),
                    state_text(c.copy.state).to_owned(),
                    c.copy.version.clone().unwrap_or_default(),
                    c.clients
                        .iter()
                        .map(|c| c.id())
                        .collect::<Vec<_>>()
                        .join(", "),
                ]
            })
            .collect::<Vec<_>>(),
    );
    for c in &copies {
        let hint = match c.copy.state {
            CopyState::Older => "`klav skill update` replaces it".to_owned(),
            CopyState::Edited if c.copy.kept_mine.is_some() => "kept as you edited it".to_owned(),
            CopyState::Edited => {
                "Klav does not overwrite it: `klav skill update --keep-mine` keeps it, `klav skill install --replace` puts Klav's back (yours is kept next to it)".to_owned()
            }
            CopyState::Unmanaged if c.copy.adoptable => {
                "it is a skill Klav published: `klav skill install --adopt` lets Klav keep it up to date".to_owned()
            }
            CopyState::Unmanaged => "Klav leaves it: `klav skill install --replace` puts Klav's there (that one is kept next to it)".to_owned(),
            CopyState::Removed => "Klav does not put it back by itself: `klav skill install` does".to_owned(),
            CopyState::Current | CopyState::Newer => continue,
        };
        output::info(&format!("{}: {hint}", c.copy.path.display()));
    }
    Ok(())
}

/// What happens to one copy.
#[derive(Serialize)]
struct Step {
    path: PathBuf,
    /// `install`, `replace`, `adopt`, `remove`, `forget`, `keep_mine`,
    /// `keep` or `leave`.
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<CopyState>,
    /// Where the copy that was there is kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    saved_as: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

impl Step {
    fn new(path: PathBuf, action: &'static str, copy: Option<&SkillCopy>) -> Self {
        Self {
            path,
            action,
            state: copy.map(|c| c.state),
            saved_as: None,
            note: None,
        }
    }

    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

fn show_steps(steps: &[Step], json: bool, dry_run: bool) -> CliResult<()> {
    if json {
        return output::json(&json!({
            "version": skill::version(),
            "dry_run": dry_run,
            "copies": steps,
        }));
    }
    for s in steps {
        let what = match s.action {
            "install" => "installs",
            "replace" => "replaces",
            "adopt" => "keeps as Klav's",
            "remove" => "removes",
            "forget" => "forgets",
            "keep_mine" => "keeps your edits in",
            "keep" => "leaves (up to date)",
            _ => "leaves",
        };
        let what = if dry_run {
            what.to_owned()
        } else {
            format!("Klav {what}")
        };
        output::info(&format!(
            "{what} {}{}{}",
            s.path.display(),
            s.saved_as
                .as_ref()
                .map(|p| format!(" (the old one is in {})", p.display()))
                .unwrap_or_default(),
            s.note
                .as_ref()
                .map(|n| format!(": {n}"))
                .unwrap_or_default()
        ));
    }
    if dry_run {
        output::info("Nothing was changed (--dry-run).");
    }
    Ok(())
}

/// The skill folders `install`/`uninstall` work on: the ones given, the
/// clients' given, or `default`.
fn places(
    env: &Env,
    place: &SkillWhere,
    default: impl FnOnce() -> CliResult<Vec<PathBuf>>,
) -> CliResult<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    for dir in &place.dirs {
        out.insert(std::path::absolute(dir)?);
    }
    for client in &place.clients {
        let dir = client.skills_dir(env).ok_or_else(|| {
            usage(format!(
                "{} has no skill folder Klav can write: the skill reaches it through the description of Klav's tools",
                client.name()
            ))
        })?;
        out.insert(dir);
    }
    if out.is_empty() {
        out.extend(default()?);
    }
    Ok(out.into_iter().collect())
}

/// `SKILL.md.mine-<time>` next to `path`, with what `path` has now.
fn keep_aside(path: &Path) -> CliResult<PathBuf> {
    let aside = path.with_file_name(format!(
        "{}.mine-{}",
        skill::FILE,
        crate::time::file_stamp(crate::time::now_ms())
    ));
    std::fs::copy(path, &aside).map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?;
    Ok(aside)
}

fn install(ctx: &Ctx, args: &SkillInstallArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let _lock = if args.dry_run {
        None
    } else {
        Some(Registry::lock(&ctx.home)?)
    };
    let mut registry = Registry::load(&ctx.home)?;
    let dirs = places(&env, &args.place, || {
        let dirs: BTreeSet<PathBuf> = ALL
            .into_iter()
            .filter(|c| c.installed(&env).is_some())
            .filter_map(|c| c.skills_dir(&env))
            .collect();
        if dirs.is_empty() {
            return Err(usage(
                "no client with a skill folder is installed here: name the folder with --dir",
            ));
        }
        Ok(dirs.into_iter().collect())
    })?;
    let mut steps = Vec::new();
    for dir in dirs {
        let path = skill::file_in(&dir);
        let copy = skill::inspect(&path, &registry);
        let step = match copy.as_ref().map(|c| c.state) {
            None | Some(CopyState::Removed) => Step::new(path, "install", copy.as_ref()),
            Some(CopyState::Older) => Step::new(path, "replace", copy.as_ref()),
            Some(CopyState::Current) => Step::new(path, "keep", copy.as_ref()),
            Some(CopyState::Newer) => Step::new(path, "keep", copy.as_ref())
                .note("it is newer than this klav's skill"),
            Some(CopyState::Edited | CopyState::Unmanaged) if args.replace => {
                Step::new(path, "replace", copy.as_ref())
            }
            Some(CopyState::Unmanaged) if args.adopt => {
                if copy.as_ref().is_some_and(|c| c.adoptable) {
                    Step::new(path, "adopt", copy.as_ref())
                } else {
                    Step::new(path, "leave", copy.as_ref()).note(
                        "it is not a skill Klav published, so Klav does not adopt it (`--replace` puts Klav's there and keeps it next to it)",
                    )
                }
            }
            Some(CopyState::Edited) => Step::new(path, "leave", copy.as_ref())
                .note("it was edited: Klav does not overwrite it (`--replace` does, keeping yours next to it)"),
            Some(CopyState::Unmanaged) => Step::new(path, "leave", copy.as_ref()).note(
                if copy.as_ref().is_some_and(|c| c.adoptable) {
                    "it is not Klav's: `--adopt` keeps it as Klav's, `--replace` puts Klav's there"
                } else {
                    "it is not Klav's: `--replace` puts Klav's there and keeps it next to it"
                },
            ),
        };
        steps.push((step, copy));
    }
    if args.dry_run {
        let steps: Vec<Step> = steps.into_iter().map(|(s, _)| s).collect();
        return show_steps(&steps, args.json.json, true);
    }
    let mut done = Vec::new();
    for (mut step, copy) in steps {
        match step.action {
            "install" => skill::write(&step.path, &mut registry)?,
            "replace" => {
                if matches!(
                    copy.as_ref().map(|c| c.state),
                    Some(CopyState::Edited | CopyState::Unmanaged)
                ) {
                    step.saved_as = Some(keep_aside(&step.path)?);
                }
                skill::write(&step.path, &mut registry)?;
            }
            "adopt" => {
                let copy = copy.as_ref().expect("adopt needs a copy");
                registry.wrote_skill(
                    &step.path,
                    copy.sha256.clone().unwrap_or_default(),
                    copy.version.as_deref().unwrap_or("0.1.0"),
                );
                if copy.version.as_deref().is_some_and(|v| {
                    skill::compare_versions(v, skill::version()) == std::cmp::Ordering::Less
                }) {
                    step.note = Some(
                        "it is older than this klav's: `klav skill update` replaces it".into(),
                    );
                }
            }
            _ => {}
        }
        done.push(step);
    }
    registry.save(&ctx.home)?;
    show_steps(&done, args.json.json, false)
}

fn update(ctx: &Ctx, args: &SkillUpdateArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let _lock = Registry::lock(&ctx.home)?;
    let mut registry = Registry::load(&ctx.home)?;
    let paths: Vec<PathBuf> = if args.dirs.is_empty() {
        registry.skills.iter().map(|s| s.path.clone()).collect()
    } else {
        args.dirs
            .iter()
            .map(|d| std::path::absolute(d).map(|d| skill::file_in(&d)))
            .collect::<Result<_, _>>()?
    };
    let _ = env;
    let mut steps = Vec::new();
    for path in paths {
        let Some(copy) = skill::inspect(&path, &registry) else {
            continue;
        };
        let step = match copy.state {
            CopyState::Older => {
                skill::write(&path, &mut registry)?;
                Step::new(path, "replace", Some(&copy))
            }
            CopyState::Current => Step::new(path, "keep", Some(&copy)),
            CopyState::Newer => Step::new(path, "keep", Some(&copy)).note("it is newer than this klav's skill"),
            CopyState::Edited if args.keep_mine => {
                if let Some(record) = registry.skill_mut(&path) {
                    record.kept_mine = Some(skill::version().to_owned());
                }
                Step::new(path, "keep_mine", Some(&copy))
            }
            CopyState::Edited if copy.kept_mine.as_deref() == Some(skill::version()) => {
                Step::new(path, "leave", Some(&copy)).note("you kept your edited copy")
            }
            CopyState::Edited => Step::new(path, "leave", Some(&copy)).note(
                "it was edited: Klav does not overwrite it (`--keep-mine` keeps it; `klav skill install --replace` puts Klav's back, keeping yours next to it)",
            ),
            CopyState::Removed => Step::new(path, "leave", Some(&copy))
                .note("it was removed: Klav does not put it back by itself (`klav skill install` does)"),
            CopyState::Unmanaged => Step::new(path, "leave", Some(&copy))
                .note("it is not Klav's (`klav skill install --adopt` or `--replace`)"),
        };
        steps.push(step);
    }
    registry.save(&ctx.home)?;
    if steps.is_empty() && !args.json.json {
        output::info("Klav has no copy of its skill to update (`klav skill install` puts one).");
        return Ok(());
    }
    show_steps(&steps, args.json.json, false)
}

fn uninstall(ctx: &Ctx, args: &SkillUninstallArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let _lock = Registry::lock(&ctx.home)?;
    let mut registry = Registry::load(&ctx.home)?;
    let dirs = places(&env, &args.place, || {
        Ok(registry
            .skills
            .iter()
            .filter_map(|s| skills_dir_of(&s.path).map(Path::to_path_buf))
            .collect())
    })?;
    let mut steps = Vec::new();
    for dir in dirs {
        let path = skill::file_in(&dir);
        let Some(copy) = skill::inspect(&path, &registry) else {
            continue;
        };
        let step = match copy.state {
            CopyState::Current | CopyState::Older | CopyState::Newer => {
                skill::remove(&path, &mut registry)?;
                Step::new(path, "remove", Some(&copy))
            }
            CopyState::Edited if args.force => {
                skill::remove(&path, &mut registry)?;
                Step::new(path, "remove", Some(&copy))
            }
            CopyState::Edited => Step::new(path, "leave", Some(&copy))
                .note("it was edited: Klav does not remove it (`--force` does)"),
            CopyState::Removed => {
                registry.forget_skill(&path);
                Step::new(path, "forget", Some(&copy))
            }
            CopyState::Unmanaged => Step::new(path, "leave", Some(&copy)).note("it is not Klav's"),
        };
        steps.push(step);
    }
    registry.save(&ctx.home)?;
    if steps.is_empty() && !args.json.json {
        output::info("There is no copy of Klav's skill to remove.");
        return Ok(());
    }
    show_steps(&steps, args.json.json, false)
}

/// For `klav agent status`: a line when a copy Klav installed is older than
/// this `klav`'s skill (ADR 0033 §6).
pub(crate) fn outdated_note(ctx: &Ctx) -> Option<String> {
    let registry = Registry::load(&ctx.home).ok()?;
    let older = registry
        .skills
        .iter()
        .filter_map(|r| skill::inspect(&r.path, &registry))
        .any(|c| c.state == CopyState::Older);
    older.then(|| {
        format!(
            "A copy of the Klav skill is older than this klav's ({}): `klav skill update` replaces it.",
            skill::version()
        )
    })
}
