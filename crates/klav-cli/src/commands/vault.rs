//! `vault` and `project`.

use klav_core::model::normalize_repo_url;

use crate::cli::{ProjectCommand, VaultCommand};
use crate::context::Ctx;
use crate::error::{CliResult, usage};
use crate::output;

pub(crate) async fn vault_cmd(ctx: &mut Ctx, cmd: VaultCommand) -> CliResult<()> {
    let backend = ctx.backend().await?;
    match cmd {
        VaultCommand::Ls(flag) => {
            let vaults = backend.vaults().await?;
            if flag.json {
                return output::json(&vaults);
            }
            let rows: Vec<Vec<String>> = vaults
                .iter()
                .map(|v| {
                    vec![
                        v.name.clone(),
                        v.items.to_string(),
                        v.id.to_string(),
                        if v.deleted {
                            "trash".into()
                        } else {
                            String::new()
                        },
                    ]
                })
                .collect();
            output::table(&["VAULT", "ITEMS", "ID", ""], &rows);
        }
        VaultCommand::Create { name } => {
            backend.create_vault(&name).await?;
            output::info(&format!(
                "Vault {name:?} created (with project \"General\")."
            ));
        }
    }
    Ok(())
}

fn split_project<'a>(vault: Option<&'a str>, project: &'a str) -> (Option<&'a str>, &'a str) {
    if vault.is_none()
        && let Some((v, p)) = project.split_once('/')
        && !v.is_empty()
        && !p.is_empty()
    {
        return (Some(v), p);
    }
    (vault, project)
}

fn resolve_repo(explicit: Option<&str>, remote: &str) -> CliResult<String> {
    if let Some(raw) = explicit {
        return normalize_repo_url(raw)
            .map_err(|_| usage(format!("invalid repository URL {raw:?}")));
    }
    let cwd = std::env::current_dir()?;
    crate::project::detect_git_repo(&cwd, remote).ok_or_else(|| {
        usage(format!(
            "could not detect a Git repository from remote {remote:?} here; pass --repo <host/owner/repo or URL>"
        ))
    })
}

pub(crate) async fn project_cmd(ctx: &mut Ctx, cmd: ProjectCommand) -> CliResult<()> {
    let backend = ctx.backend().await?;
    match cmd {
        ProjectCommand::Ls { vault, json } => {
            let projects = backend.projects(vault.as_deref()).await?;
            if json.json {
                return output::json(&projects);
            }
            let any_repos = projects.iter().any(|p| !p.repos.is_empty());
            let rows: Vec<Vec<String>> = projects
                .iter()
                .map(|p| {
                    if any_repos {
                        vec![
                            p.vault.clone(),
                            p.name.clone(),
                            p.repos.join(", "),
                            p.id.to_string(),
                        ]
                    } else {
                        vec![p.vault.clone(), p.name.clone(), p.id.to_string()]
                    }
                })
                .collect();
            if any_repos {
                output::table(&["VAULT", "PROJECT", "REPOS", "ID"], &rows);
            } else {
                output::table(&["VAULT", "PROJECT", "ID"], &rows);
            }
        }
        ProjectCommand::Create { vault, name } => {
            backend.create_project(vault.as_deref(), &name).await?;
            output::info(&format!("Project {name:?} created."));
        }
        ProjectCommand::Link {
            project,
            vault,
            repo,
            remote,
            json,
        } => {
            let repo = resolve_repo(repo.as_deref(), &remote)?;
            let (vault_arg, project_arg) = split_project(vault.as_deref(), &project);
            let existing = backend.projects(vault_arg).await?;
            let current = existing
                .iter()
                .find(|p| {
                    p.id.to_string().eq_ignore_ascii_case(project_arg)
                        || p.name.eq_ignore_ascii_case(project_arg)
                })
                .cloned();
            let mut repos = current.map(|p| p.repos).unwrap_or_default();
            if !repos.contains(&repo) {
                repos.push(repo.clone());
            }
            let updated = backend
                .set_project_repos(vault_arg, project_arg, repos)
                .await?;
            if json.json {
                return output::json(&updated);
            }
            output::info(&format!(
                "Linked {repo} to {}/{}.",
                updated.vault, updated.name
            ));
        }
        ProjectCommand::Unlink {
            project,
            vault,
            repo,
            remote,
            json,
        } => {
            let repo = resolve_repo(repo.as_deref(), &remote)?;
            let (vault_arg, project_arg) = split_project(vault.as_deref(), &project);
            let existing = backend.projects(vault_arg).await?;
            let current = existing
                .iter()
                .find(|p| {
                    p.id.to_string().eq_ignore_ascii_case(project_arg)
                        || p.name.eq_ignore_ascii_case(project_arg)
                })
                .cloned();
            let mut repos = current.map(|p| p.repos).unwrap_or_default();
            let before = repos.len();
            repos.retain(|r| r != &repo);
            let updated = backend
                .set_project_repos(vault_arg, project_arg, repos)
                .await?;
            if json.json {
                return output::json(&updated);
            }
            if updated.repos.len() < before {
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
        }
    }
    Ok(())
}
