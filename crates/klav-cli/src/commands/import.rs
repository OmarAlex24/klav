//! `klav import`: exports of Bitwarden, 1Password, Google Authenticator
//! and browsers (ADR 0024). Shows what will happen (new, merged, already
//! there), then imports. Prints titles, user names and sites, never values.

use std::io::IsTerminal;

use klav_client::import::{ImportPreview, ImportResult};
use klav_client::klav_import::{Action, Change, Source, read_wiping};
use zeroize::Zeroizing;

use crate::backend::ImportFile;
use crate::cli::ImportArgs;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;

/// The longest file read (a `.1pux` with attachments can be large).
const MAX_FILE: u64 = klav_client::klav_import::MAX_FILE as u64;

fn read_files(ctx: &mut Ctx, args: &ImportArgs) -> CliResult<Vec<ImportFile>> {
    let mut files = Vec::new();
    for path in &args.files {
        if path.as_os_str() == "-" {
            if std::io::stdin().is_terminal() {
                output::info(
                    "Paste the otpauth-migration:// links (one per QR code), then press Ctrl-D:",
                );
            }
            let text = ctx.input.stdin_rest()?;
            files.push(ImportFile {
                name: "stdin".into(),
                data: Zeroizing::new(text.as_bytes().to_vec()),
            });
            continue;
        }
        let name = path.display().to_string();
        let file = std::fs::File::open(path)
            .map_err(|e| CliError::Other(format!("cannot open {name}: {e}")))?;
        // Sized from the file up front: `read_to_end` into an empty buffer
        // would grow it by doubling and free each smaller copy unwiped.
        let hint = file
            .metadata()
            .map_or(0, |m| usize::try_from(m.len()).unwrap_or(usize::MAX));
        let limit = MAX_FILE as usize + 1;
        let data = read_wiping(file, hint, limit)
            .map_err(|e| CliError::Other(format!("cannot read {name}: {e}")))?;
        if data.len() as u64 > MAX_FILE {
            return Err(CliError::Other(format!("{name} is too large to import")));
        }
        files.push(ImportFile { name, data });
    }
    Ok(files)
}

fn action(a: Action) -> &'static str {
    match a {
        Action::New => "new",
        Action::Merge => "merge",
        Action::Duplicate => "already there",
    }
}

fn change(c: Change) -> &'static str {
    match c {
        Change::PasswordAdded => "password added",
        Change::PasswordReplaced => "new password (the old one goes to its history)",
        Change::PasswordKept => "Klav's password is newer (the imported one goes to its history)",
        Change::HistoryAdded => "earlier passwords added to its history",
        Change::TotpAdded => "one-time code added",
        Change::TotpSecond => "a second one-time code added",
        Change::UrlsAdded => "sites added",
        Change::NotesAdded => "notes added",
        Change::FieldsAdded => "fields added",
        Change::TagsAdded => "tags added",
        Change::Renamed => "title taken: renamed",
        Change::TotpItem => "one-time code with no matching login: its own item",
        Change::PasskeyAdded => "passkey added",
        Change::PasskeyKept => "it already has another passkey, which stays",
        Change::PasskeyOtherSite => "its passkey is for another site: not imported",
    }
}

fn print_preview(preview: &ImportPreview) {
    for s in &preview.sources {
        output::info(&format!(
            "{}: {}, {} entr{}",
            s.name,
            s.format.name(),
            s.items,
            if s.items == 1 { "y" } else { "ies" }
        ));
        for r in &s.skipped {
            output::warn(&format!(
                "{}, {}: not imported ({})",
                s.name, r.at, r.reason
            ));
        }
        for r in &s.notes {
            output::warn(&format!("{}, {}: {}", s.name, r.at, r.reason));
        }
        if s.more_remarks > 0 {
            output::warn(&format!(
                "{}: {} more rows skipped or shortened (not listed)",
                s.name, s.more_remarks
            ));
        }
    }
    let rows: Vec<Vec<String>> = preview
        .rows
        .iter()
        .map(|r| {
            let mut what: Vec<String> = Vec::new();
            if r.action == Action::Merge && r.target != r.title {
                what.push(format!("into {:?}", r.target));
            }
            if r.action == Action::Duplicate && r.target != r.title {
                what.push(format!("same as {:?}", r.target));
            }
            if r.action == Action::New && r.target != r.title {
                what.push(format!("as {:?}", r.target));
            }
            what.extend(r.changes.iter().map(|c| match c {
                // Named, so a file cannot add a site unseen (T119).
                Change::UrlsAdded if !r.sites_added.is_empty() => {
                    format!("sites added: {}", r.sites_added.join(", "))
                }
                c => change(*c).to_owned(),
            }));
            vec![
                action(r.action).to_owned(),
                r.title.clone(),
                r.username.clone().unwrap_or_default(),
                r.host.clone().unwrap_or_default(),
                what.join("; "),
            ]
        })
        .collect();
    if !rows.is_empty() {
        output::info("");
        output::table(&["ACTION", "TITLE", "USER", "SITE", "DETAILS"], &rows);
    }
    if preview.rows_total > preview.rows.len() {
        output::info(&format!(
            "… and {} more.",
            preview.rows_total - preview.rows.len()
        ));
    }
    output::info("");
    output::info(&format!(
        "Into {} / {}: {} new, {} merged, {} already there. The same site and user merge into one item; a replaced password stays in that item's password history.",
        preview.vault,
        preview.project,
        preview.totals.new,
        preview.totals.merged,
        preview.totals.duplicates
    ));
    if preview.passkeys > 0 {
        output::warn(&format!(
            "{} passkey(s) were not imported: the file does not carry their keys, or they are not valid (see the notes). Sign in on each site and save a new passkey.",
            preview.passkeys
        ));
    }
    for m in &preview.missing {
        let positions = m
            .missing
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        output::warn(&format!(
            "the Google Authenticator export has {} QR codes and {} {} not here yet: import {} too (running again later is fine).",
            m.size,
            if m.missing.len() == 1 {
                "number"
            } else {
                "numbers"
            },
            positions,
            if m.missing.len() == 1 { "it" } else { "them" },
        ));
    }
}

fn print_result(done: &ImportResult) {
    output::info(&format!(
        "Imported into {} / {}: {} item(s) created, {} updated, {} already there.",
        done.vault, done.project, done.created, done.updated, done.totals.duplicates
    ));
    if !done.passkeys_failed.is_empty() {
        output::warn("Some passkeys could not be saved; their logins were imported without them:");
        for why in &done.passkeys_failed {
            output::warn(&format!("  {why}"));
        }
    }
}

pub(crate) async fn import_cmd(ctx: &mut Ctx, args: ImportArgs) -> CliResult<()> {
    let from = args
        .from
        .as_deref()
        .map(|f| {
            Source::parse(f).ok_or_else(|| {
                usage(format!(
                    "unknown --from {f:?}: use bitwarden, 1password, google, chrome, edge, brave, firefox, safari or csv"
                ))
            })
        })
        .transpose()?;
    // Files (and stdin) first: the master password may follow on stdin.
    let files = read_files(ctx, &args)?;
    let (vault, project) = (args.vault.as_deref(), args.project.as_deref());
    let backend = ctx.backend().await?;
    let pending = backend
        .import_load(&files, from, args.from.as_deref())
        .await?;
    drop(files);
    let preview = backend.import_preview(&pending, vault, project).await?;
    if args.dry_run {
        backend.import_cancel(&pending).await?;
        if args.json {
            return output::json(&serde_json::json!({ "preview": preview }));
        }
        print_preview(&preview);
        output::info("Nothing imported (--dry-run).");
        return Ok(());
    }
    if !args.json {
        print_preview(&preview);
    }
    let done = backend.import_apply(&pending, vault, project).await?;
    if args.json {
        output::json(&serde_json::json!({ "preview": preview, "result": done }))?;
    } else {
        print_result(&done);
    }
    if args.files.iter().any(|p| p.as_os_str() != "-") {
        output::info(
            "Delete the export files now (and empty the trash): they hold your passwords in plain text.",
        );
    }
    Ok(())
}
