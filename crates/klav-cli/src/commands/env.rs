//! `klav env …`: environments per repository (ADR 0032 §2, §6 and §8) and
//! `klav env scan` (ADR 0036 §16). Secrets never come from argv, and no
//! value is printed except by `klav env show --reveal`: not in the import's
//! review, not in its errors, not by `scan`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use klav_client::environments::{
    EnvironmentEdit, EnvironmentSaved, ImportReview, ImportStatus, NewVariable, VariableOrigin,
};
use klav_client::ops::SecretText;
use zeroize::Zeroizing;

use crate::cli::EnvCommand;
use crate::context::Ctx;
use crate::dotenv;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::project;

/// Directories `klav env scan` never walks into.
const SKIPPED_DIRS: [&str; 3] = [".git", "target", "node_modules"];

/// Where the remote chosen for a repository is remembered (ADR 0032 §2):
/// repository root → remote name.
const REMOTES_FILE: &str = "repo-remotes.json";

pub(crate) async fn env_cmd(ctx: &mut Ctx, cmd: EnvCommand) -> CliResult<()> {
    match cmd {
        EnvCommand::Ls { project, json } => {
            let project = project.or_else(toml_project);
            let list = ctx
                .backend()
                .await?
                .environments(project.as_deref())
                .await?;
            if json.json {
                return output::json(&list);
            }
            if list.is_empty() {
                output::info(
                    "No environments yet: `klav env create NAME` or `klav env import .env --env NAME`.",
                );
                return Ok(());
            }
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|e| {
                    vec![
                        e.name.clone(),
                        format!("{}/{}", e.vault, e.project),
                        e.variables.to_string(),
                        if e.protected {
                            "protected".into()
                        } else {
                            String::new()
                        },
                        crate::time::format_utc_minutes(e.updated_at),
                    ]
                })
                .collect();
            output::table(
                &["ENVIRONMENT", "PROJECT", "VARIABLES", "", "LAST EDIT"],
                &rows,
            );
            Ok(())
        }
        EnvCommand::Show {
            name,
            project,
            reveal,
            json,
        } => show(ctx, project.or_else(toml_project), &name, reveal, json.json).await,
        EnvCommand::Create {
            name,
            project,
            protected,
            no_protected,
        } => {
            let edit = EnvironmentEdit {
                create: true,
                must_be_new: true,
                protected: match (protected, no_protected) {
                    (true, _) => Some(true),
                    (_, true) => Some(false),
                    _ => None,
                },
                ..EnvironmentEdit::default()
            };
            let saved = save(ctx, project.or_else(toml_project), &name, &edit).await?;
            output::info(&format!(
                "Environment “{name}” created{}.",
                if saved.protected {
                    " (protected: presence every time, and ask once for agents)"
                } else {
                    ""
                }
            ));
            report(&saved);
            Ok(())
        }
        EnvCommand::Set {
            name,
            project,
            secret,
            secret_stdin,
            refs,
            protected,
        } => {
            let project = project.or_else(toml_project);
            let mut set = Vec::new();
            for var in &secret {
                let value = ctx.input.prompt_hidden(&format!("{var}: "))?;
                set.push(NewVariable {
                    name: var.clone(),
                    value: Some(SecretText::new(value.as_str())),
                    reference: None,
                });
            }
            for var in &secret_stdin {
                let value = ctx.input.stdin_line(var)?;
                set.push(NewVariable {
                    name: var.clone(),
                    value: Some(SecretText::new(value.as_str())),
                    reference: None,
                });
            }
            let short = toml_project();
            for pair in &refs {
                let (var, reference) = pair
                    .split_once('=')
                    .ok_or_else(|| usage("--ref expects VAR=klav://…"))?;
                let reference = project::expand(short.as_deref(), reference)
                    .map_err(|e| usage(format!("--ref {var}: {e}")))?;
                set.push(NewVariable {
                    name: var.to_owned(),
                    value: None,
                    reference: Some(reference),
                });
            }
            if set.is_empty() && protected.is_none() {
                return Err(usage(
                    "nothing to set: use -s VAR, --secret-stdin VAR or --ref VAR=REF",
                ));
            }
            let names: Vec<String> = set.iter().map(|v| v.name.clone()).collect();
            let edit = EnvironmentEdit {
                create: true,
                protected,
                set,
                ..EnvironmentEdit::default()
            };
            let saved = save(ctx, project, &name, &edit).await?;
            if !names.is_empty() {
                output::info(&format!("Set {} in “{name}”.", names.join(", ")));
            }
            report(&saved);
            Ok(())
        }
        EnvCommand::Rm {
            name,
            vars,
            project,
            yes,
        } => {
            let project = project.or_else(toml_project);
            if !vars.is_empty() {
                let edit = EnvironmentEdit {
                    remove: vars.clone(),
                    ..EnvironmentEdit::default()
                };
                let saved = save(ctx, project, &name, &edit).await?;
                output::info(&format!("Removed {} from “{name}”.", vars.join(", ")));
                report(&saved);
                return Ok(());
            }
            if !yes {
                match ctx.input.question(&format!(
                    "Move the environment “{name}” and all its variables to the trash? [y/N] "
                ))? {
                    Some(a) if is_yes(&a) => {}
                    Some(_) => return Err(usage("cancelled")),
                    None => return Err(usage("no terminal to confirm: pass --yes")),
                }
            }
            let (backend, input, home) = ctx.parts().await?;
            let saved = backend
                .environment_trash(home, input, project.as_deref(), &name)
                .await?;
            output::info(&format!("Environment “{name}” moved to the trash."));
            report(&saved);
            Ok(())
        }
        EnvCommand::Import {
            file,
            env,
            project,
            dry_run,
            yes,
            json,
        } => {
            import(
                ctx,
                &ImportArgs {
                    file,
                    env,
                    project: project.or_else(toml_project),
                    dry_run,
                    yes,
                    json: json.json,
                },
            )
            .await
        }
        EnvCommand::Link {
            project,
            remote,
            yes,
        } => link(ctx, project, remote, yes).await,
        EnvCommand::Unlink { project, remote } => unlink(ctx, project, remote).await,
        EnvCommand::Scan { dir, json } => scan(ctx, dir, json.json).await,
    }
}

/// `klav.toml`'s `project`, when one applies here.
fn toml_project() -> Option<String> {
    project::load(None).ok().flatten().and_then(|c| c.project)
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    )
}

/// Saves a change, with presence when it lowers the protection.
async fn save(
    ctx: &mut Ctx,
    project: Option<String>,
    name: &str,
    edit: &EnvironmentEdit,
) -> CliResult<EnvironmentSaved> {
    let (backend, input, home) = ctx.parts().await?;
    backend
        .environment_save(home, input, project.as_deref(), name, edit)
        .await
}

fn quoted_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("“{n}”"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a save did to the protection, and to whom (ADR 0032 §6).
fn report(saved: &EnvironmentSaved) {
    let agents = if saved.agents.is_empty() {
        String::new()
    } else {
        format!(" for {}", quoted_list(&saved.agents))
    };
    if !saved.newly_protected.is_empty() {
        output::info(&format!(
            "{} {} now protected{agents}: copying or showing it asks for your presence every \
             time, and agents need an approval for each use.",
            quoted_list(&saved.newly_protected),
            if saved.newly_protected.len() == 1 {
                "is"
            } else {
                "are"
            },
        ));
    } else if saved.protected && !saved.agents.is_empty() {
        output::info(&format!(
            "The grants of {} were issued again first.",
            quoted_list(&saved.agents)
        ));
    }
    if !saved.unprotected.is_empty() {
        output::info(&format!(
            "“{}” no longer protects {}.",
            saved.name,
            quoted_list(&saved.unprotected)
        ));
    }
    for w in &saved.warnings {
        output::warn(w);
    }
}

async fn show(
    ctx: &mut Ctx,
    project: Option<String>,
    name: &str,
    reveal: bool,
    json: bool,
) -> CliResult<()> {
    let backend = ctx.backend().await?;
    let detail = backend
        .environment(project.as_deref(), name)
        .await?
        .ok_or_else(|| CliError::Other(format!("no environment {name:?} in this project")))?;
    if let Some(changes) = &detail.agent_changes {
        output::warn(&agent_changes_text(changes));
    }
    let values: Option<Vec<Zeroizing<String>>> = if reveal {
        let references: Vec<String> = detail.variables.iter().map(|v| v.resolve.clone()).collect();
        let resolved = if references.is_empty() {
            Vec::new()
        } else {
            backend.resolve(&references).await?
        };
        let mut out = Vec::new();
        for r in &resolved {
            out.push(Zeroizing::new(r.text()?.to_owned()));
        }
        Some(out)
    } else {
        None
    };
    if json {
        let variables: Vec<serde_json::Value> = detail
            .variables
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let mut entry = serde_json::to_value(v).unwrap_or_default();
                if let (Some(values), Some(obj)) = (&values, entry.as_object_mut()) {
                    obj.insert(
                        "value".into(),
                        serde_json::Value::String(values[i].to_string()),
                    );
                }
                entry
            })
            .collect();
        return output::json(&serde_json::json!({
            "environment": detail.listing,
            "variables": variables,
            "agent_changes": detail.agent_changes,
        }));
    }
    output::info(&format!(
        "{}/{} › {}{}",
        detail.listing.vault,
        detail.listing.project,
        detail.listing.name,
        if detail.listing.protected {
            " (protected)"
        } else {
            ""
        }
    ));
    let rows: Vec<Vec<String>> = detail
        .variables
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let value = match &values {
                Some(values) => values[i].to_string(),
                None => "••••••••".into(),
            };
            vec![v.name.clone(), origin_text(&v.origin), value]
        })
        .collect();
    output::table(&["VARIABLE", "FROM", "VALUE"], &rows);
    Ok(())
}

/// Where a variable comes from, in words.
pub(crate) fn origin_text(origin: &VariableOrigin) -> String {
    match origin {
        VariableOrigin::Value => "value".into(),
        VariableOrigin::Reference {
            target, protected, ..
        } => format!(
            "→ {}{}",
            target
                .as_deref()
                .unwrap_or("an item this device does not see"),
            if *protected { " (protected)" } else { "" }
        ),
    }
}

/// «DATABASE_URL and REDIS_URL were changed by “mi-agente” on …» (ADR 0032
/// §3, answer 7).
pub(crate) fn agent_changes_text(changes: &klav_client::environments::AgentChanges) -> String {
    let who = changes.agent.as_deref().map_or_else(
        || format!("agent {}", changes.agent_id),
        |n| format!("“{n}”"),
    );
    let names = match changes.variables.as_slice() {
        [one] => one.clone(),
        many => {
            let (last, rest) = many.split_last().expect("not empty");
            format!("{} and {last}", rest.join(", "))
        }
    };
    format!(
        "{names} {} changed by {who} on {}, since your last version",
        if changes.variables.len() == 1 {
            "was"
        } else {
            "were"
        },
        crate::time::format_utc_minutes(changes.at)
    )
}

// ------------------------------------------------------------- import --

struct ImportArgs {
    file: String,
    env: String,
    project: Option<String>,
    dry_run: bool,
    yes: bool,
    json: bool,
}

/// Whether `path` is a `klav.toml` (by name: never by trying to parse a
/// `.env` as TOML, whose error could quote a value).
fn is_klav_toml(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|n| n == project::FILE_NAME)
}

/// Reads a file into a wiped buffer; the error never quotes its content.
fn read_secret_file(path: &Path) -> CliResult<Zeroizing<String>> {
    let bytes = Zeroizing::new(
        std::fs::read(path).map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?,
    );
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.to_owned())),
        Err(_) => Err(CliError::Other(format!(
            "{}: not UTF-8 text",
            path.display()
        ))),
    }
}

async fn import(ctx: &mut Ctx, args: &ImportArgs) -> CliResult<()> {
    if is_klav_toml(&args.file) {
        return import_klav_toml(ctx, args).await;
    }
    let (label, text) = if args.file == "-" {
        ("stdin".to_owned(), ctx.input.stdin_rest()?)
    } else {
        let path = PathBuf::from(&args.file);
        (path.display().to_string(), read_secret_file(&path)?)
    };
    let mut repeated = Vec::new();
    let variables = dotenv::parse(&text, &mut repeated)
        .map_err(|e| CliError::Other(format!("{label}: {e}")))?;
    drop(text);
    for name in &repeated {
        output::warn(&format!(
            "{label}: {name} appears more than once; the later value is used"
        ));
    }
    if variables.is_empty() {
        return Err(CliError::Other(format!("{label}: no variables")));
    }
    let pairs: Vec<(String, SecretText)> = variables
        .iter()
        .map(|v| (v.name.clone(), SecretText::new(v.value.as_str())))
        .collect();
    let review = ctx
        .backend()
        .await?
        .import_review(args.project.as_deref(), &args.env, &pairs)
        .await?;
    let protected_env = ctx
        .backend()
        .await?
        .environments(args.project.as_deref())
        .await
        .ok()
        .and_then(|l| l.into_iter().find(|e| e.name == args.env))
        .map_or(
            klav_core::model::environment::is_production_name(&args.env),
            |e| e.protected,
        );
    if args.json {
        output::json(&review)?;
    } else {
        print_review(&review, &args.env, protected_env);
    }
    if args.dry_run {
        output::info("Dry run: nothing was changed.");
        return Ok(());
    }
    let changes = review
        .iter()
        .filter(|r| r.status != ImportStatus::Same)
        .count();
    if changes == 0 {
        output::info(&format!("“{}” already has these values.", args.env));
        return Ok(());
    }
    let matches = review
        .iter()
        .filter(|r| r.status != ImportStatus::Same && r.matches.is_some())
        .count();
    let mut as_references = true;
    if !args.yes {
        match ctx.input.question(&format!(
            "Import {changes} variable(s) into “{}”? [y/N] ",
            args.env
        ))? {
            Some(a) if is_yes(&a) => {}
            Some(_) => return Err(usage("cancelled")),
            None => {
                return Err(usage(
                    "no terminal to confirm the import: review it with --dry-run and pass --yes",
                ));
            }
        }
        if matches > 0 {
            as_references = match ctx.input.question(&format!(
                "Store the {matches} value(s) that match an existing field as references to it \
                 instead of copies? [Y/n] "
            ))? {
                Some(a) => a.is_empty() || is_yes(&a),
                None => true,
            };
        }
    }
    let mut set = Vec::new();
    for (var, r) in variables.iter().zip(&review) {
        if r.status == ImportStatus::Same {
            continue;
        }
        set.push(match (&r.matches, as_references) {
            (Some(m), true) => NewVariable {
                name: var.name.clone(),
                value: None,
                reference: Some(m.reference.clone()),
            },
            _ => NewVariable {
                name: var.name.clone(),
                value: Some(SecretText::new(var.value.as_str())),
                reference: None,
            },
        });
    }
    drop(pairs);
    drop(variables);
    let edit = EnvironmentEdit {
        create: true,
        set,
        ..EnvironmentEdit::default()
    };
    let saved = save(ctx, args.project.clone(), &args.env, &edit).await?;
    output::info(&format!(
        "Imported {changes} variable(s) into “{}”{}.",
        args.env,
        if saved.created {
            " (new environment)"
        } else {
            ""
        }
    ));
    report(&saved);
    if args.file != "-" {
        offer_delete(ctx, Path::new(&args.file), args.yes)?;
    }
    Ok(())
}

fn print_review(review: &[ImportReview], env: &str, protected: bool) {
    output::info(&format!("Review for “{env}” (no value is shown):"));
    for r in review {
        let status = match r.status {
            ImportStatus::New => "new",
            ImportStatus::Changed => "changes",
            ImportStatus::Same => "same",
        };
        output::info(&format!("  {status:<8} {}", r.name));
        if let Some(m) = &r.matches
            && r.status != ImportStatus::Same
        {
            output::info(&format!(
                "           same value as {}: proposed as a reference instead of a copy{}",
                m.name,
                if protected && !m.protected {
                    " (that item becomes protected)"
                } else {
                    ""
                }
            ));
        }
    }
}

/// After an import, offers to delete the `.env` (ADR 0032 §6): `[y/N]`,
/// with what deleting does and doesn't do.
fn offer_delete(ctx: &mut Ctx, path: &Path, yes: bool) -> CliResult<()> {
    let tracked = git_state(path) == GitState::Tracked;
    if yes {
        output::info(&format!(
            "{} is still there: delete it once you use `klav run`{}.",
            path.display(),
            if tracked {
                "; git tracks it, so its values are in the history: rotate them"
            } else {
                ""
            }
        ));
        return Ok(());
    }
    let mut prompt = format!("Delete {}? ", path.display());
    if tracked {
        prompt.push_str(
            "Git tracks it: deleting it does not take it out of the history, so rotate these \
             values. ",
        );
    }
    prompt.push_str("Deleting is an unlink, not a secure erase. [y/N] ");
    match ctx.input.question(&prompt)? {
        Some(a) if is_yes(&a) => {
            std::fs::remove_file(path)
                .map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?;
            output::info(&format!("Deleted {}.", path.display()));
        }
        _ => output::info(&format!("{} was kept.", path.display())),
    }
    Ok(())
}

/// `klav env import klav.toml --env NAME` (ADR 0032 §8): the flat `[env]`
/// as references, never copying a value, then the offer to switch the file
/// to `default_env`.
async fn import_klav_toml(ctx: &mut Ctx, args: &ImportArgs) -> CliResult<()> {
    let path = PathBuf::from(&args.file);
    let config = project::load(Some(&path))?.ok_or_else(|| usage("no klav.toml"))?;
    if config.env.is_empty() {
        return Err(usage(format!(
            "{}: no flat [env] variables to import",
            path.display()
        )));
    }
    let project = args.project.clone().or_else(|| config.project.clone());
    output::info(&format!(
        "Review for “{}” (references only, no value is copied):",
        args.env
    ));
    for (name, reference) in &config.env {
        output::info(&format!("  reference {name} → {reference}"));
    }
    if args.dry_run {
        output::info("Dry run: nothing was changed.");
        return Ok(());
    }
    if !args.yes {
        match ctx.input.question(&format!(
            "Create these {} reference(s) in “{}”? [y/N] ",
            config.env.len(),
            args.env
        ))? {
            Some(a) if is_yes(&a) => {}
            Some(_) => return Err(usage("cancelled")),
            None => return Err(usage("no terminal to confirm: pass --yes")),
        }
    }
    let edit = EnvironmentEdit {
        create: true,
        set: config
            .env
            .iter()
            .map(|(name, reference)| NewVariable {
                name: name.clone(),
                value: None,
                reference: Some(reference.clone()),
            })
            .collect(),
        ..EnvironmentEdit::default()
    };
    let saved = save(ctx, project, &args.env, &edit).await?;
    output::info(&format!(
        "Imported {} reference(s) into “{}”.",
        config.env.len(),
        args.env
    ));
    report(&saved);
    let rewrite = if args.yes {
        true
    } else {
        matches!(
            ctx.input.question(&format!(
                "Change {} to `default_env = \"{}\"` (its flat [env] goes away)? [y/N] ",
                path.display(),
                args.env
            ))?,
            Some(a) if is_yes(&a)
        )
    };
    if rewrite {
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(&path, project::migrated_text(&text, &args.env)?)?;
        output::info(&format!(
            "{} now says default_env = \"{}\"; `klav run` asks to confirm it once.",
            path.display(),
            args.env
        ));
    }
    Ok(())
}

// --------------------------------------------------------------- link --

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The repository's root, its remote's normalized identifier and the
/// remote's name (ADR 0032 §2): `--remote`, the one remembered for this
/// repository, `origin`, or the person's choice when `origin` is missing
/// among several remotes or a fork's `upstream` differs.
fn repository(
    ctx: &mut Ctx,
    remote: Option<String>,
    ask: bool,
) -> CliResult<(PathBuf, String, String)> {
    let cwd = std::env::current_dir()?;
    let root = git(&cwd, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .ok_or_else(|| usage("not inside a Git repository"))?;
    let remotes_path = ctx.home.file(REMOTES_FILE);
    let mut remembered: BTreeMap<String, String> = std::fs::read(&remotes_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let key = root.display().to_string();
    let url_of = |name: &str| project::detect_git_repo(&root, name);
    let chosen = match remote.or_else(|| remembered.get(&key).cloned()) {
        Some(name) => name,
        None => {
            let names: Vec<String> = git(&root, &["remote"])
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            let origin = names.iter().any(|n| n == "origin");
            let upstream = names.iter().any(|n| n == "upstream");
            let differs = origin && upstream && url_of("origin") != url_of("upstream");
            if origin && !differs {
                "origin".to_owned()
            } else if names.len() == 1 {
                names[0].clone()
            } else if names.is_empty() {
                return Err(usage("this repository has no Git remote"));
            } else {
                let listed = names
                    .iter()
                    .map(|n| format!("{n} ({})", url_of(n).unwrap_or_else(|| "?".into())))
                    .collect::<Vec<_>>()
                    .join(", ");
                let answer = if ask {
                    ctx.input
                        .question(&format!("Which remote is this repository? {listed}: "))?
                } else {
                    None
                };
                let Some(answer) = answer.filter(|a| names.contains(a)) else {
                    return Err(usage(format!(
                        "several remotes ({listed}): pass --remote NAME"
                    )));
                };
                remembered.insert(key.clone(), answer.clone());
                ctx.home.ensure()?;
                klav_client::home::write_private(
                    &remotes_path,
                    &serde_json::to_vec_pretty(&remembered).map_err(|e| usage(e.to_string()))?,
                )?;
                answer
            }
        }
    };
    let repo = url_of(&chosen).ok_or_else(|| {
        usage(format!(
            "cannot read a repository URL from the remote {chosen:?}"
        ))
    })?;
    Ok((root, repo, chosen))
}

fn split_project(wanted: &str) -> CliResult<(String, String)> {
    let wanted = wanted.trim_matches('/');
    wanted
        .split_once('/')
        .filter(|(v, p)| !v.is_empty() && !p.is_empty())
        .map(|(v, p)| (v.to_owned(), p.to_owned()))
        .ok_or_else(|| usage("write the project as Vault/Project"))
}

async fn link(
    ctx: &mut Ctx,
    project: Option<String>,
    remote: Option<String>,
    yes: bool,
) -> CliResult<()> {
    let config = project::load(None)?;
    let wanted = project
        .or_else(|| config.as_ref().and_then(|c| c.project.clone()))
        .ok_or_else(|| usage("which project? `klav env link Vault/Project`"))?;
    let (vault, name) = split_project(&wanted)?;
    let (root, repo, remote) = repository(ctx, remote, !yes)?;
    let backend = ctx.backend().await?;
    let current = backend
        .projects(Some(&vault))
        .await?
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(&name) || p.id.to_string() == name)
        .ok_or_else(|| CliError::Other(format!("no project {wanted:?}")))?;
    let mut repos = current.repos.clone();
    if !repos.contains(&repo) {
        repos.push(repo.clone());
    }
    let updated = backend
        .set_project_repos(Some(&vault), &name, repos)
        .await?;
    output::info(&format!(
        "Linked {repo} (remote {remote}) to {}/{}. It only suggests the project: it never grants \
         anything or skips `klav run`'s confirmation.",
        updated.vault, updated.name
    ));
    let has_project = config.as_ref().is_some_and(|c| c.project.is_some());
    if !has_project && !yes {
        let file = config
            .as_ref()
            .map_or_else(|| root.join(project::FILE_NAME), |c| c.path.clone());
        if let Some(a) = ctx.input.question(&format!(
            "Write project = \"{}/{}\" in {}? [y/N] ",
            updated.vault,
            updated.name,
            file.display()
        ))? && is_yes(&a)
        {
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let mut doc: toml_edit::DocumentMut = text
                .parse()
                .map_err(|_| usage("klav.toml does not parse"))?;
            doc["project"] = toml_edit::value(format!("{}/{}", updated.vault, updated.name));
            std::fs::write(&file, doc.to_string())?;
            output::info(&format!("Wrote {}.", file.display()));
        }
    }
    Ok(())
}

async fn unlink(ctx: &mut Ctx, project: Option<String>, remote: Option<String>) -> CliResult<()> {
    let wanted = project
        .or_else(toml_project)
        .ok_or_else(|| usage("which project? `klav env unlink --project Vault/Project`"))?;
    let (vault, name) = split_project(&wanted)?;
    let (_, repo, _) = repository(ctx, remote, true)?;
    let backend = ctx.backend().await?;
    let current = backend
        .projects(Some(&vault))
        .await?
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(&name) || p.id.to_string() == name)
        .ok_or_else(|| CliError::Other(format!("no project {wanted:?}")))?;
    let before = current.repos.len();
    let repos: Vec<String> = current.repos.into_iter().filter(|r| r != &repo).collect();
    let after = repos.len();
    let updated = backend
        .set_project_repos(Some(&vault), &name, repos)
        .await?;
    if after < before {
        output::info(&format!(
            "Unlinked {repo} from {}/{}.",
            updated.vault, updated.name
        ));
    } else {
        output::info(&format!(
            "{repo} was not linked to {}/{}.",
            updated.vault, updated.name
        ));
    }
    Ok(())
}

// --------------------------------------------------------------- scan --

/// What git says of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GitState {
    /// Git tracks it: its values are in the history.
    Tracked,
    /// `.gitignore` covers it.
    Ignored,
    /// Neither: the next `git add .` takes it.
    Untracked,
    /// Not inside a Git repository.
    NoRepository,
}

pub(crate) fn git_state(path: &Path) -> GitState {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return GitState::NoRepository;
    };
    if git(dir, &["rev-parse", "--git-dir"]).is_none() {
        return GitState::NoRepository;
    }
    if git(dir, &["ls-files", "--error-unmatch", "--", name]).is_some() {
        return GitState::Tracked;
    }
    let ignored = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["check-ignore", "-q", "--", name])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ignored {
        GitState::Ignored
    } else {
        GitState::Untracked
    }
}

/// Whether `name` is a `.env` file `scan` reports: `.env` or `.env.*`,
/// except `.env.example`.
pub(crate) fn is_env_file(name: &str) -> bool {
    name == ".env" || (name.starts_with(".env.") && name != ".env.example")
}

/// The `.env` files under `dir`: regular files only (by
/// `symlink_metadata`: a link is never followed, a `.env` directory is a
/// virtualenv), never opened.
pub(crate) fn find_env_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if meta.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_ref()) {
                    stack.push(path);
                }
            } else if meta.is_file() && is_env_file(&name) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[derive(serde::Serialize)]
struct Found {
    path: String,
    git: GitState,
}

async fn scan(ctx: &mut Ctx, dir: Option<PathBuf>, json: bool) -> CliResult<()> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    let found: Vec<Found> = find_env_files(&dir)
        .iter()
        .map(|p| Found {
            path: p.display().to_string(),
            git: git_state(p),
        })
        .collect();
    if json {
        return output::json(&found);
    }
    if found.is_empty() {
        output::info(&format!("No .env files under {}.", dir.display()));
        return Ok(());
    }
    let rows: Vec<Vec<String>> = found
        .iter()
        .map(|f| {
            vec![
                f.path.clone(),
                match f.git {
                    GitState::Tracked => {
                        "TRACKED by git: its values are in the history, rotate them".into()
                    }
                    GitState::Ignored => "ignored by git".into(),
                    GitState::Untracked => "not ignored: `git add .` would take it".into(),
                    GitState::NoRepository => "not in a git repository".into(),
                },
            ]
        })
        .collect();
    output::table(&["FILE", "GIT"], &rows);
    for f in &found {
        let Some(answer) = ctx.input.question(&format!(
            "Import {} into an environment? Its name (empty: skip): ",
            f.path
        ))?
        else {
            output::info("Import them with `klav env import FILE --env NAME`.");
            return Ok(());
        };
        if answer.is_empty() {
            continue;
        }
        Box::pin(import(
            ctx,
            &ImportArgs {
                file: f.path.clone(),
                env: answer,
                project: toml_project(),
                dry_run: false,
                yes: false,
                json: false,
            },
        ))
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_files_scan_reports() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file("env"));
        assert!(!is_env_file(".envrc"));
    }

    #[test]
    fn scan_never_follows_links_or_takes_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".env"), "A=1").unwrap();
        std::fs::write(root.join(".env.example"), "A=").unwrap();
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::write(root.join("app/.env.local"), "B=2").unwrap();
        // A virtualenv called `.env`, and skipped trees.
        std::fs::create_dir_all(root.join("py/.env/bin")).unwrap();
        for skipped in SKIPPED_DIRS {
            std::fs::create_dir_all(root.join(skipped)).unwrap();
            std::fs::write(root.join(skipped).join(".env"), "C=3").unwrap();
        }
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join(".env"), "D=4").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("linked")).unwrap();
        std::os::unix::fs::symlink(outside.path().join(".env"), root.join(".env.link")).unwrap();
        let found: Vec<String> = find_env_files(root)
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert_eq!(found, vec![".env".to_owned(), "app/.env.local".to_owned()]);
    }
}
