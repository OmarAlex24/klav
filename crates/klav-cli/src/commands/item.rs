//! `item …` and `totp`.

use klav_client::ItemFilter;
use klav_client::ops::{FieldInput, ItemPatch, ItemView, NewItem, SecretText};
use klav_core::model::item::ItemKind;
use secrecy::ExposeSecret;

use crate::cli::{FieldArgs, ItemCommand, KindArg, ListKindArg, TotpArgs};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::input::Input;
use crate::output;

pub(crate) fn kind(arg: KindArg) -> ItemKind {
    match arg {
        KindArg::Login => ItemKind::Login,
        KindArg::Card => ItemKind::Card,
        KindArg::Identity => ItemKind::Identity,
        KindArg::SshKey => ItemKind::SshKey,
        KindArg::Totp => ItemKind::Totp,
        KindArg::Note => ItemKind::Note,
        KindArg::ApiKey => ItemKind::ApiKey,
    }
}

fn list_kind(arg: ListKindArg) -> ItemKind {
    match arg {
        ListKindArg::Login => ItemKind::Login,
        ListKindArg::Card => ItemKind::Card,
        ListKindArg::Identity => ItemKind::Identity,
        ListKindArg::SshKey => ItemKind::SshKey,
        ListKindArg::File => ItemKind::File,
        ListKindArg::Totp => ItemKind::Totp,
        ListKindArg::Note => ItemKind::Note,
        ListKindArg::ApiKey => ItemKind::ApiKey,
    }
}

/// The type filters of `item ls`. One type goes in `kind`, which every
/// klavd understands; several, in `kinds`.
fn kind_filter(args: &[ListKindArg]) -> (Option<ItemKind>, Vec<ItemKind>) {
    let mut kinds: Vec<ItemKind> = Vec::new();
    for k in args.iter().copied().map(list_kind) {
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    match kinds.as_slice() {
        [one] => (Some(*one), Vec::new()),
        _ => (None, kinds),
    }
}

fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::Card => "card",
        ItemKind::Identity => "identity",
        ItemKind::SshKey => "ssh-key",
        ItemKind::File => "file",
        ItemKind::Totp => "totp",
        ItemKind::Note => "note",
        ItemKind::ApiKey => "api-key",
        ItemKind::GeneratorHistory => "generator-history",
        ItemKind::Preferences => "preferences",
        ItemKind::AgentLabels => "agent-labels",
    }
}

/// Collects field values: plain ones from argv, secret ones from the TTY,
/// stdin or the generator. Values are read in a fixed order: secrets on the
/// TTY, then `--secret-stdin` lines, then the notes.
fn collect(
    input: &mut Input,
    args: &FieldArgs,
) -> CliResult<(Vec<FieldInput>, Option<SecretText>)> {
    let mut out = Vec::new();
    for pair in &args.fields {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| usage(format!("--field expects NAME=VALUE, got {pair:?}")))?;
        out.push(FieldInput {
            name: name.trim().to_owned(),
            value: SecretText::new(value),
            kind: None,
            secret: false,
        });
    }
    for name in &args.secrets {
        let value = input.prompt_hidden(&format!("{name}: "))?;
        out.push(FieldInput {
            name: name.clone(),
            value: SecretText::new(value.as_str()),
            kind: None,
            secret: true,
        });
    }
    for name in &args.secrets_stdin {
        let value = input.stdin_line(&format!("value of {name}"))?;
        out.push(FieldInput {
            name: name.clone(),
            value: SecretText::new(value.as_str()),
            kind: None,
            secret: true,
        });
    }
    // A generated password follows the rules of the item's site (smart).
    let site = klav_core::generator::SiteHints {
        host: args.urls.iter().find_map(|u| klav_core::site::item_host(u)),
        ..Default::default()
    };
    for name in &args.generate {
        let value = klav_core::generator::generate(&Default::default(), &site)
            .map_err(|e| CliError::Other(e.to_string()))?
            .value;
        out.push(FieldInput {
            name: name.clone(),
            value: SecretText::new(value.expose_secret()),
            kind: None,
            secret: true,
        });
    }
    let notes = if args.notes_stdin {
        Some(SecretText::new(input.stdin_rest()?.as_str()))
    } else {
        None
    };
    Ok((out, notes))
}

/// The name of the agent that wrote an item's current version, for its
/// pending sites (the ID if the agents cannot be listed).
async fn agent_name(ctx: &mut Ctx, agent: Option<klav_core::ids::AgentId>) -> Option<String> {
    let agent = agent?;
    let name = match super::agent::agents(ctx).await {
        Ok(all) => all.into_iter().find(|a| a.id == agent).map(|a| a.name),
        Err(_) => None,
    };
    Some(name.unwrap_or_else(|| agent.to_string()))
}

/// Confirmed sites, then those an agent added (ADR 0030 §7).
fn print_sites(s: &klav_client::ItemSummary, added_by: Option<&str>) {
    if !s.confirmed_urls.is_empty() {
        output::line(&format!("urls:      {}", s.confirmed_urls.join(", ")));
    }
    if !s.pending_urls.is_empty() {
        output::line(&format!(
            "sites added by {} (not confirmed, never filled): {}",
            added_by.unwrap_or("an agent"),
            s.pending_urls.join(", ")
        ));
        output::line(&format!(
            "           confirm: klav item sites {} --confirm · remove: klav item sites {} --remove URL",
            s.id, s.id
        ));
    }
}

fn print_view(view: &ItemView, added_by: Option<&str>) {
    let s = &view.summary;
    output::line(&format!("{}  ({})", s.title, kind_name(s.kind)));
    output::line(&s.reference);
    output::line(&format!("id:        {}", s.id));
    output::line(&format!("version:   {}", s.version));
    if s.trashed {
        output::line("state:     in the trash");
    }
    for f in &view.fields {
        let attachment = (f.kind == klav_core::model::item::FieldKind::File)
            .then(|| {
                view.attachments.iter().find(|a| {
                    f.value
                        .as_ref()
                        .is_some_and(|v| v.expose() == a.id.to_string())
                })
            })
            .flatten();
        let shown = match (&f.value, f.filled, f.secret) {
            (_, false, _) => "(empty)".to_owned(),
            _ if attachment.is_some() => {
                let a = attachment.expect("checked");
                format!(
                    "file {} ({} bytes; use klav inject -r)",
                    a.file_name, a.size
                )
            }
            (Some(v), _, _) => v.expose().to_owned(),
            (None, true, true) => "•••••••• (hidden; use --reveal)".to_owned(),
            (None, true, false) => String::new(),
        };
        output::line(&format!("{:<10} {shown}", format!("{}:", f.name)));
    }
    print_sites(s, added_by);
    if !s.tags.is_empty() {
        output::line(&format!("tags:      {}", s.tags.join(", ")));
    }
    match (&view.notes, view.has_notes) {
        (Some(n), _) => output::line(&format!("notes:\n{}", n.expose())),
        (None, true) => output::line("notes:     (hidden; use --reveal)"),
        (None, false) => {}
    }
}

fn print_list(items: &[klav_client::ItemSummary]) {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            vec![
                i.reference.clone(),
                kind_name(i.kind).to_owned(),
                i.username.clone().unwrap_or_default(),
            ]
        })
        .collect();
    output::table(&["ITEM", "TYPE", "USERNAME"], &rows);
}

/// Splits `klav://v/p/i/field` into the item part and the field.
fn split_field_ref(item: &str) -> Option<(String, String)> {
    let scheme = klav_core::model::reference::SCHEME;
    let rest = item
        .get(..scheme.len())
        .filter(|p| p.eq_ignore_ascii_case(scheme))
        .map(|_| &item[scheme.len()..])?;
    let parts: Vec<&str> = rest.split('/').collect();
    (parts.len() == 4).then(|| {
        (
            format!("klav://{}", parts[..3].join("/")),
            parts[3].to_owned(),
        )
    })
}

pub(crate) async fn item_cmd(ctx: &mut Ctx, cmd: ItemCommand) -> CliResult<()> {
    match cmd {
        ItemCommand::Add {
            kind: k,
            title,
            vault,
            project,
            username,
            allow_duplicate,
            fields,
            json,
        } => {
            let (mut inputs, notes) = collect(&mut ctx.input, &fields)?;
            if let Some(u) = username {
                inputs.insert(
                    0,
                    FieldInput {
                        name: "username".into(),
                        value: SecretText::new(u),
                        kind: None,
                        secret: false,
                    },
                );
            }
            let new = NewItem {
                kind: kind(k),
                title,
                vault,
                project,
                fields: inputs,
                urls: fields.urls,
                tags: fields.tags,
                notes,
                allow_duplicate,
            };
            // Validate locally before asking for the password.
            klav_client::ops::build_item(&new)?;
            let summary = ctx.backend().await?.create(&new).await?;
            if json.json {
                return output::json(&summary);
            }
            output::info(&format!("Added {}", summary.reference));
        }
        ItemCommand::Get {
            item,
            reveal,
            field,
            json,
        } => {
            let (item, field) = match (field, split_field_ref(&item)) {
                (Some(f), _) => (item, Some(f)),
                (None, Some((i, f))) => (i, Some(f)),
                (None, None) => (item, None),
            };
            let backend = ctx.backend().await?;
            let view = backend.view(&item, reveal).await?;
            if let Some(name) = field {
                let f = view
                    .fields
                    .iter()
                    .find(|f| f.name == name || f.id.to_string() == name)
                    .ok_or_else(|| {
                        usage(format!("no field {name:?} in {}", view.summary.reference))
                    })?;
                let value = match &f.value {
                    Some(v) => v.expose().to_owned(),
                    None if f.secret && f.filled => {
                        return Err(usage(format!("{name} is secret: add --reveal to print it")));
                    }
                    None => String::new(),
                };
                if json.json {
                    return output::json(&serde_json::json!({
                        "reference": format!("{}/{}", view.summary.reference, f.name),
                        "kind": f.kind,
                        "value": value,
                    }));
                }
                output::line(&value);
                return Ok(());
            }
            if json.json {
                return output::json(&view);
            }
            let added_by = agent_name(ctx, view.summary.author_agent_id).await;
            print_view(&view, added_by.as_deref());
        }
        ItemCommand::Edit {
            item,
            title,
            allow_duplicate,
            remove,
            fields,
            json,
        } => {
            let (set, notes) = collect(&mut ctx.input, &fields)?;
            let patch = ItemPatch {
                title,
                set,
                remove,
                add_urls: fields.urls,
                remove_urls: Vec::new(),
                add_tags: fields.tags,
                notes,
                allow_duplicate,
            };
            let summary = ctx.backend().await?.edit(&item, &patch).await?;
            if json.json {
                return output::json(&summary);
            }
            output::info(&format!(
                "Updated {} (version {})",
                summary.reference, summary.version
            ));
        }
        ItemCommand::Attach {
            item,
            field,
            path,
            name,
            json,
        } => {
            let meta =
                std::fs::metadata(&path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
            if meta.len() > klav_client::MAX_ATTACHMENT_BYTES as u64 {
                return Err(usage(format!(
                    "{} is too large (limit {} MiB)",
                    path.display(),
                    klav_client::MAX_ATTACHMENT_BYTES / (1024 * 1024)
                )));
            }
            let content = zeroize::Zeroizing::new(std::fs::read(&path)?);
            let file_name = match name {
                Some(n) => n,
                None => path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .ok_or_else(|| usage("give the file a name with --name"))?,
            };
            let summary = ctx
                .backend()
                .await?
                .attach(&item, &field, &file_name, &content)
                .await?;
            if json.json {
                return output::json(&summary);
            }
            output::info(&format!(
                "Attached {file_name} ({} bytes) to {}/{field}",
                content.len(),
                summary.reference
            ));
        }
        ItemCommand::Sites {
            item,
            confirm,
            remove,
            json,
        } => {
            let summary = if confirm || !remove.is_empty() {
                // Confirming is an ordinary edit by the person: the new
                // version is hers, so all its sites are confirmed.
                let patch = ItemPatch {
                    remove_urls: remove,
                    ..ItemPatch::default()
                };
                ctx.backend().await?.edit(&item, &patch).await?
            } else {
                ctx.backend().await?.view(&item, false).await?.summary
            };
            if json.json {
                return output::json(&summary);
            }
            output::line(&summary.reference);
            let added_by = agent_name(ctx, summary.author_agent_id).await;
            print_sites(&summary, added_by.as_deref());
            if summary.urls.is_empty() {
                output::line("(no sites)");
            }
        }
        ItemCommand::Rm { item } => {
            let summary = ctx.backend().await?.trash(&item).await?;
            output::info(&format!(
                "Moved {} to the trash (kept 30 days).",
                summary.reference
            ));
        }
        ItemCommand::Ls {
            vault,
            project,
            kind: k,
            codes,
            tag,
            trash,
            json,
        } => {
            let (kind, kinds) = kind_filter(&k);
            let filter = ItemFilter {
                vault,
                project,
                kind,
                kinds,
                codes,
                tag,
                query: None,
                trash,
            };
            let items = ctx.backend().await?.list(&filter).await?;
            if json.json {
                return output::json(&items);
            }
            print_list(&items);
        }
        ItemCommand::Search { query, json } => {
            let filter = ItemFilter {
                query: Some(query),
                ..ItemFilter::default()
            };
            let items = ctx.backend().await?.list(&filter).await?;
            if json.json {
                return output::json(&items);
            }
            print_list(&items);
        }
        ItemCommand::History { item, reveal, json } => {
            let backend = ctx.backend().await?;
            if let Some(index) = reveal {
                let value = backend.previous_password(&item, index).await?;
                output::line(value.expose());
                return Ok(());
            }
            let history = backend.password_history(&item).await?;
            if json.json {
                return output::json(&history);
            }
            if history.entries.is_empty() {
                output::info("No previous passwords.");
            } else {
                let rows: Vec<Vec<String>> = history
                    .entries
                    .iter()
                    .map(|p| {
                        vec![
                            p.index.to_string(),
                            if p.unconfirmed {
                                format!("{} (generated, not confirmed)", p.label)
                            } else {
                                p.label.clone()
                            },
                            p.from_ms.map(crate::time::format_utc).unwrap_or_default(),
                            crate::time::format_utc(p.to_ms),
                            "••••••••".to_owned(),
                        ]
                    })
                    .collect();
                output::table(&["N", "FIELD", "FROM", "UNTIL", "VALUE"], &rows);
                output::info("Use --reveal N to print one.");
            }
            if history.pending {
                output::info(
                    "An assisted change left a new password pending: decide in the item's card (extension or app) whether the site took it.",
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn totp_cmd(ctx: &mut Ctx, args: TotpArgs) -> CliResult<()> {
    let code = ctx
        .backend()
        .await?
        .totp(&args.item, args.field.as_deref())
        .await?;
    if args.json.json {
        return output::json(&code);
    }
    output::line(code.code.expose());
    output::info(&format!("(valid for {} s)", code.remaining));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_references_split() {
        assert_eq!(
            split_field_ref("klav://a/b/c/password"),
            Some(("klav://a/b/c".into(), "password".into()))
        );
        assert_eq!(split_field_ref("klav://a/b/c"), None);
        assert_eq!(split_field_ref("GitHub"), None);
    }

    #[test]
    fn one_kind_goes_in_kind_and_several_in_kinds() {
        use ListKindArg as L;
        assert_eq!(kind_filter(&[]), (None, vec![]));
        assert_eq!(kind_filter(&[L::Login]), (Some(ItemKind::Login), vec![]));
        assert_eq!(
            kind_filter(&[L::Login, L::Login]),
            (Some(ItemKind::Login), vec![])
        );
        assert_eq!(
            kind_filter(&[L::SshKey, L::Note, L::SshKey]),
            (None, vec![ItemKind::SshKey, ItemKind::Note])
        );
    }

    #[test]
    fn kinds_parse_with_commas_and_plurals() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "klav",
            "item",
            "ls",
            "--kind",
            "logins,ssh",
            "--kind",
            "api-key",
            "--codes",
        ])
        .expect("parses");
        let crate::cli::Command::Item(ItemCommand::Ls { kind, codes, .. }) = cli.command else {
            panic!("not item ls");
        };
        assert_eq!(
            kind,
            vec![ListKindArg::Login, ListKindArg::SshKey, ListKindArg::ApiKey]
        );
        assert!(codes);
        assert!(
            crate::cli::Cli::try_parse_from(["klav", "item", "ls", "--kind", "codes"]).is_err()
        );
    }
}
