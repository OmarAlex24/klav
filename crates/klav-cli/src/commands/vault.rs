//! `vault` and `project`.

use crate::cli::{ProjectCommand, VaultCommand};
use crate::context::Ctx;
use crate::error::CliResult;
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

pub(crate) async fn project_cmd(ctx: &mut Ctx, cmd: ProjectCommand) -> CliResult<()> {
    let backend = ctx.backend().await?;
    match cmd {
        ProjectCommand::Ls { vault, json } => {
            let projects = backend.projects(vault.as_deref()).await?;
            if json.json {
                return output::json(&projects);
            }
            let rows: Vec<Vec<String>> = projects
                .iter()
                .map(|p| vec![p.vault.clone(), p.name.clone(), p.id.to_string()])
                .collect();
            output::table(&["VAULT", "PROJECT", "ID"], &rows);
        }
        ProjectCommand::Create { vault, name } => {
            backend.create_project(vault.as_deref(), &name).await?;
            output::info(&format!("Project {name:?} created."));
        }
    }
    Ok(())
}
