//! `klav inject`: writes a template with its `{{ klav://… }}` references
//! replaced, or the value of one reference (`-r`, files included), to
//! stdout, a new 0600 file (optionally removed after `--ttl`) or a named
//! pipe read once (`--fifo`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use klav_core::model::item::FieldKind;
use klav_sdk::template::{self, Piece};
use zeroize::Zeroizing;

use crate::cli::InjectArgs;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::project;
use crate::secret_files::{
    Cleanup, Signals, human, warn_if_not_ignored, warn_leftovers, write_new_private,
};

/// How long `--fifo` waits for a reader without `--ttl`.
const FIFO_WAIT: Duration = Duration::from_secs(600);

pub(crate) async fn inject_cmd(ctx: &mut Ctx, args: InjectArgs) -> CliResult<()> {
    if args.ttl.is_some() && args.out.is_none() {
        return Err(usage("--ttl needs --out-file"));
    }
    let config = project::load(args.config.as_deref())?;
    let project_name = config.as_ref().and_then(|c| c.project.clone());
    let content: Zeroizing<Vec<u8>> = if let Some(name) = &args.environment {
        dotenv_content(ctx, config.as_ref(), name, args.trust).await?
    } else {
        match &args.reference {
            Some(reference) => {
                let reference =
                    project::expand(project_name.as_deref(), reference).map_err(usage)?;
                let mut resolved = ctx.backend().await?.resolve(&[reference]).await?;
                let value = resolved.pop().ok_or_else(|| usage("nothing resolved"))?;
                Zeroizing::new(value.value.expose().to_vec())
            }
            None => {
                let template = match &args.template {
                    Some(path) => Zeroizing::new(
                        std::fs::read_to_string(path)
                            .map_err(|e| usage(format!("{}: {e}", path.display())))?,
                    ),
                    None => ctx.input.stdin_rest()?,
                };
                render(ctx, &template).await?
            }
        }
    };
    ctx.close();

    let Some(out) = args.out else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&content)?;
        stdout.flush()?;
        return Ok(());
    };
    // Handle signals before anything exists on disk, so that a signal
    // arriving right after the write still triggers the cleanup.
    let mut signals = Signals::new()?;
    if args.fifo {
        return serve_fifo(
            &out,
            content,
            args.ttl.unwrap_or(FIFO_WAIT),
            args.force,
            &mut signals,
        )
        .await;
    }
    let mut cleanup = Cleanup::default();
    let written = write_new_private(&out, &content, args.force);
    drop(content);
    warn_leftovers(
        &[&out],
        written
            .as_ref()
            .err()
            .and_then(CliError::message)
            .as_deref(),
    );
    written?;
    let Some(ttl) = args.ttl else {
        warn_if_not_ignored(&out);
        output::info(&format!(
            "Wrote {} (mode 0600). It is plain text on disk: delete it when done.",
            out.display()
        ));
        return Ok(());
    };
    cleanup.add(out.clone());
    warn_if_not_ignored(&out);
    output::info(&format!(
        "Wrote {} (mode 0600); removing it in {} (Ctrl-C removes it now).",
        out.display(),
        human(ttl)
    ));
    tokio::select! {
        () = tokio::time::sleep(ttl) => {}
        _ = signals.recv() => {}
    }
    cleanup.remove_all();
    output::info(&format!("Removed {}.", out.display()));
    Ok(())
}

/// Environment `name` as a `.env` (ADR 0032 §6): its variables from the
/// vault and `[env.name]`, confirmed once per `klav.toml` text like `klav
/// run`, with presence every time for a protected one.
async fn dotenv_content(
    ctx: &mut Ctx,
    config: Option<&project::ProjectConfig>,
    name: &str,
    trust: bool,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let chosen =
        crate::commands::run::environment_variables(ctx, config, name, Default::default(), &[])
            .await?;
    project::confirm_environment(&ctx.home, config, &chosen.confirmation, trust)?;
    crate::commands::run::before_presence(&chosen);
    let names: Vec<String> = chosen.env.keys().cloned().collect();
    let references: Vec<String> = chosen.env.values().cloned().collect();
    let resolved = if references.is_empty() {
        Vec::new()
    } else {
        ctx.backend().await?.resolve(&references).await?
    };
    let mut variables = Vec::with_capacity(names.len());
    for (name, value) in names.into_iter().zip(&resolved) {
        if value.kind == FieldKind::File {
            return Err(usage(format!(
                "{name}: {} is a file: write it with klav inject -r … -o <path>",
                value.canonical
            )));
        }
        variables.push((name, Zeroizing::new(value.text()?.to_owned())));
    }
    Ok(crate::dotenv::render(&variables))
}

/// Replaces every `{{ klav://… }}` in `template`; other `{{ … }}` blocks
/// (other template languages) are left alone.
async fn render(ctx: &mut Ctx, template: &str) -> CliResult<Zeroizing<Vec<u8>>> {
    let pieces = template::parse(template).map_err(usage)?;
    let references = template::references(&pieces);
    let values = if references.is_empty() {
        Vec::new()
    } else {
        ctx.backend().await?.resolve(&references).await?
    };
    let mut out = Zeroizing::new(Vec::with_capacity(template.len()));
    let mut values = values.iter();
    for piece in &pieces {
        match piece {
            Piece::Text(text) => out.extend_from_slice(text.as_bytes()),
            Piece::Reference(_) => {
                let value = values.next().ok_or_else(|| usage("nothing resolved"))?;
                if value.kind == FieldKind::File {
                    return Err(usage(format!(
                        "{} is a file: write it with klav inject -r … -o <path>",
                        value.canonical
                    )));
                }
                out.extend_from_slice(value.text()?.as_bytes());
            }
        }
    }
    Ok(out)
}

/// The device and inode of the pipe `klav` made.
type FifoId = (u64, u64);

/// Makes a pipe at `path` that only its owner can use. Without `force` it
/// fails if anything is there (no check-then-create window); with it the
/// pipe is made under a temporary name beside it and renamed over, so the
/// name is never free for another process to take.
fn make_fifo(path: &Path, force: bool) -> CliResult<FifoId> {
    use nix::errno::Errno;
    use nix::sys::stat::Mode;
    use std::os::unix::fs::MetadataExt;
    let mode = Mode::S_IRUSR | Mode::S_IWUSR;
    let made = if force {
        let name = path
            .file_name()
            .ok_or_else(|| usage(format!("{} is not a file name", path.display())))?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".{}.fifo", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        nix::unistd::mkfifo(&tmp, mode)
            .map_err(|e| usage(format!("cannot create the pipe {}: {e}", tmp.display())))?;
        let meta = std::fs::symlink_metadata(&tmp);
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(usage(format!("cannot replace {}: {e}", path.display())));
        }
        meta?
    } else {
        match nix::unistd::mkfifo(path, mode) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                return Err(usage(format!(
                    "{} already exists (use --force to replace it)",
                    path.display()
                )));
            }
            Err(e) => {
                return Err(usage(format!(
                    "cannot create the pipe {}: {e}",
                    path.display()
                )));
            }
        }
        std::fs::symlink_metadata(path)?
    };
    Ok((made.dev(), made.ino()))
}

/// Opens for writing the pipe [`make_fifo`] made, and nothing else: not a
/// symbolic link put in its place (`O_NOFOLLOW`), nor another file or pipe.
/// Blocks until a reader opens it.
fn open_fifo(path: &Path, made: FifoId) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    let pipe = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let meta = pipe.metadata()?;
    if !meta.file_type().is_fifo() || (meta.dev(), meta.ino()) != made {
        return Err(std::io::Error::other(
            "the pipe was replaced by something else: nothing written",
        ));
    }
    Ok(pipe)
}

/// Serves `content` once through a named pipe at `path`, then removes it.
async fn serve_fifo(
    path: &Path,
    content: Zeroizing<Vec<u8>>,
    wait: Duration,
    force: bool,
    signals: &mut Signals,
) -> CliResult<()> {
    let made = make_fifo(path, force)?;
    let mut cleanup = Cleanup::default();
    cleanup.add(path.to_path_buf());
    output::info(&format!(
        "Serving the secret through the pipe {} (read once; waiting up to {}).",
        path.display(),
        human(wait)
    ));

    let cancelled = Arc::new(AtomicBool::new(false));
    let writer = {
        let path: PathBuf = path.to_path_buf();
        let cancelled = Arc::clone(&cancelled);
        tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
            // Blocks until a reader opens the pipe.
            let mut pipe = open_fifo(&path, made)?;
            if cancelled.load(Ordering::SeqCst) {
                return Ok(false);
            }
            pipe.write_all(&content)?;
            Ok(true)
        })
    };
    tokio::pin!(writer);
    let outcome = tokio::select! {
        done = &mut writer => Some(done),
        () = tokio::time::sleep(wait) => None,
        _ = signals.recv() => None,
    };
    let result = match outcome {
        Some(done) => done.map_err(|e| CliError::Other(e.to_string()))?,
        None => {
            cancelled.store(true, Ordering::SeqCst);
            // Unblock the writer's open() with a reader of our own.
            {
                use std::os::unix::fs::OpenOptionsExt;
                let _reader = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                    .open(path);
                let _ = (&mut writer).await;
            }
            Ok(false)
        }
    };
    cleanup.remove_all();
    match result {
        Ok(true) => {
            output::info("Secret delivered; pipe removed.");
            Ok(())
        }
        Ok(false) => Err(CliError::Other(format!(
            "nobody read {}; pipe removed",
            path.display()
        ))),
        Err(e) => Err(CliError::Other(format!("pipe {}: {e}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_writer_opens_only_the_pipe_it_made() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let made = make_fifo(&path, false).unwrap();
        assert!(make_fifo(&path, false).is_err());
        // A symbolic link put in its place is not followed.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert!(open_fifo(&path, made).is_err());
        // Nor another file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        assert!(open_fifo(&path, made).is_err());
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"");
        // --force replaces what is there with a new pipe.
        make_fifo(&path, true).unwrap();
        use std::os::unix::fs::FileTypeExt;
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
