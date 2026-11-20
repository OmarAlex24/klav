//! `generated`: the generator history (ADR 0022 §2).

use klav_client::history::{GeneratedSelection, GeneratedView};

use crate::cli::GeneratedCommand;
use crate::context::Ctx;
use crate::error::{CliError, CliResult};
use crate::output;
use crate::time::format_utc;

fn entry_at(entries: &[GeneratedView], index: usize) -> CliResult<&GeneratedView> {
    entries.get(index).ok_or_else(|| {
        CliError::Usage(format!(
            "no entry {index} in the generator history (see klav generated ls)"
        ))
    })
}

pub(crate) async fn generated_cmd(ctx: &mut Ctx, cmd: GeneratedCommand) -> CliResult<()> {
    let backend = ctx.backend().await?;
    let entries = backend.generator_history().await?;
    match cmd {
        GeneratedCommand::Ls { json } => {
            if json.json {
                return output::json(&entries);
            }
            if entries.is_empty() {
                output::info("The generator history is empty.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let saved = match (&e.saved_in_title, e.saved_in) {
                        (Some(title), _) => title.clone(),
                        (None, Some(id)) => id.to_string(),
                        (None, None) => String::new(),
                    };
                    vec![
                        i.to_string(),
                        format_utc(e.created_at),
                        e.host.clone().unwrap_or_default(),
                        if e.pending {
                            "yes".into()
                        } else {
                            String::new()
                        },
                        saved,
                    ]
                })
                .collect();
            output::table(&["N", "GENERATED", "SITE", "PENDING", "SAVED IN"], &rows);
        }
        GeneratedCommand::Show { index } => {
            let created_at = entry_at(&entries, index)?.created_at;
            let value = backend.generated_value(created_at).await?;
            output::line(value.expose());
        }
        GeneratedCommand::Rm { index, all } => {
            let which = if all {
                GeneratedSelection::All
            } else {
                GeneratedSelection::Some(
                    index
                        .iter()
                        .map(|&i| entry_at(&entries, i).map(|e| e.created_at))
                        .collect::<CliResult<_>>()?,
                )
            };
            let removed = backend.delete_generated(which).await?;
            output::info(&format!(
                "Deleted {removed} {} from the generator history.",
                if removed == 1 { "entry" } else { "entries" }
            ));
        }
    }
    Ok(())
}
