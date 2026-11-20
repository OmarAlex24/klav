//! `klav extension install-host | uninstall-host | host-status`: native
//! messaging host manifests for the browser extension (ADR 0017 §4,
//! `docs/extension.md`).
//!
//! The browser starts the host with a fixed path and no arguments of ours,
//! and without our environment. So the manifest points to a small wrapper,
//! written into `$KLAV_HOME/native-host/`, that runs `klav-native-host`
//! with this `KLAV_HOME` and the allowed extensions.

use std::path::{Path, PathBuf};

use klav_daemon::native::{
    Caller, DEV_CHROMIUM_ID, HOST_NAME, caller_allowed, default_allowed, install_hint,
};
use serde::Serialize;

use crate::cli::{Browser, ExtensionCommand, HostArgs};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;

/// Where a browser looks for the manifests of the current user.
fn browser_dir(browser: Browser, home: &Path) -> Option<PathBuf> {
    let mac = home.join("Library/Application Support");
    let linux = home.join(".config");
    let path = if cfg!(target_os = "macos") {
        match browser {
            Browser::Chrome => mac.join("Google/Chrome"),
            Browser::Chromium => mac.join("Chromium"),
            Browser::Brave => mac.join("BraveSoftware/Brave-Browser"),
            Browser::Arc => mac.join("Arc/User Data"),
            Browser::Edge => mac.join("Microsoft Edge"),
            Browser::Dia => mac.join("Dia/User Data"),
            Browser::Firefox => mac.join("Mozilla"),
        }
    } else {
        match browser {
            Browser::Chrome => linux.join("google-chrome"),
            Browser::Chromium => linux.join("chromium"),
            Browser::Brave => linux.join("BraveSoftware/Brave-Browser"),
            Browser::Edge => linux.join("microsoft-edge"),
            Browser::Firefox => home.join(".mozilla"),
            Browser::Arc | Browser::Dia => return None,
        }
    };
    Some(path)
}

fn hosts_dir(browser: Browser, data_dir: &Path) -> PathBuf {
    if browser == Browser::Firefox && !cfg!(target_os = "macos") {
        data_dir.join("native-messaging-hosts")
    } else {
        data_dir.join("NativeMessagingHosts")
    }
}

const ALL: [Browser; 7] = [
    Browser::Chrome,
    Browser::Chromium,
    Browser::Brave,
    Browser::Arc,
    Browser::Edge,
    Browser::Dia,
    Browser::Firefox,
];

fn browser_name(b: Browser) -> &'static str {
    match b {
        Browser::Chrome => "chrome",
        Browser::Chromium => "chromium",
        Browser::Brave => "brave",
        Browser::Arc => "arc",
        Browser::Edge => "edge",
        Browser::Dia => "dia",
        Browser::Firefox => "firefox",
    }
}

/// A manifest file to write or remove.
struct Target {
    browser: Browser,
    path: PathBuf,
    /// Firefox's format (`allowed_extensions`) instead of Chromium's
    /// (`allowed_origins`).
    firefox: bool,
}

/// The manifest files to write or remove, one per path.
///
/// Dia on macOS takes its host from Mozilla's directory, in Firefox's
/// format, and ignores the one in `Dia/User Data` (checked with Dia's
/// build of 2026-11: a probe host in each directory, only Mozilla's ran).
/// So `dia` writes both; the Mozilla one is the same file Firefox reads.
fn targets(args: &HostArgs) -> CliResult<Vec<Target>> {
    if let Some(dir) = &args.user_data_dir {
        let browser = match args.browser.as_slice() {
            [] => Browser::Chromium,
            [Browser::Firefox] | [_, _, ..] => {
                return Err(usage(
                    "--user-data-dir is for one Chromium-based browser (Firefox reads its hosts from one place)",
                ));
            }
            [b] => *b,
        };
        return Ok(vec![Target {
            browser,
            path: dir
                .join("NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json")),
            firefox: false,
        }]);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| usage("HOME is not set"))?;
    let explicit = !args.browser.is_empty();
    let wanted: Vec<Browser> = if explicit {
        args.browser.clone()
    } else {
        ALL.to_vec()
    };
    let mut out: Vec<Target> = Vec::new();
    let mut push = |target: Target| {
        if !out.iter().any(|t| t.path == target.path) {
            out.push(target);
        }
    };
    for browser in wanted {
        let Some(data) = browser_dir(browser, &home) else {
            if explicit {
                return Err(usage(format!(
                    "{} is not available on this system",
                    browser_name(browser)
                )));
            }
            continue;
        };
        // Without --browser, only the browsers that are installed (their
        // data directory exists).
        if !explicit && !data.is_dir() {
            continue;
        }
        push(Target {
            browser,
            path: hosts_dir(browser, &data).join(format!("{HOST_NAME}.json")),
            firefox: browser == Browser::Firefox,
        });
        if browser == Browser::Dia
            && let Some(mozilla) = browser_dir(Browser::Firefox, &home)
        {
            push(Target {
                browser,
                path: hosts_dir(Browser::Firefox, &mozilla).join(format!("{HOST_NAME}.json")),
                firefox: true,
            });
        }
    }
    Ok(out)
}

/// The host binary's file name.
fn host_file_name() -> String {
    format!("klav-native-host{}", std::env::consts::EXE_SUFFIX)
}

/// The host binary: `--host`, next to `klav`, or in `PATH`.
fn host_binary(explicit: Option<&Path>) -> CliResult<PathBuf> {
    let name = host_file_name();
    let candidate = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => std::env::current_exe()
            .ok()
            .map(|exe| std::fs::canonicalize(&exe).unwrap_or(exe))
            .map(|exe| exe.with_file_name(&name))
            .filter(|p| p.is_file())
            .or_else(|| {
                std::env::var_os("PATH").and_then(|paths| {
                    std::env::split_paths(&paths)
                        .map(|dir| dir.join(&name))
                        .find(|p| p.is_file())
                })
            }),
    };
    let path = candidate.ok_or_else(|| {
        usage("klav-native-host not found: install it next to klav, or pass --host PATH")
    })?;
    let path =
        std::fs::canonicalize(&path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    if !path.is_file() {
        return Err(usage(format!("{} is not a file", path.display())));
    }
    Ok(path)
}

/// Single-quotes `text` for `sh`.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Allowed extensions: `(chromium origins, firefox ids)`. The Chromium
/// development build first, only with `dev` (its ID comes from a public
/// key); then the host's defaults (the store builds and the Firefox add-on,
/// `klav_daemon::native::default_allowed`); then `extra` (`--extension-id`).
fn allowed(extra: &[String], dev: bool) -> CliResult<(Vec<String>, Vec<String>)> {
    let (store, mut firefox): (Vec<String>, Vec<String>) = default_allowed()
        .into_iter()
        .partition(|id| id.starts_with("chrome-extension://"));
    let mut origins: Vec<String> = dev
        .then(|| format!("chrome-extension://{DEV_CHROMIUM_ID}/"))
        .into_iter()
        .chain(store)
        .collect();
    for id in extra {
        let id = id.trim();
        let bare = id
            .strip_prefix("chrome-extension://")
            .map(|r| r.trim_end_matches('/'))
            .unwrap_or(id);
        if bare.len() == 32 && bare.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
            let origin = format!("chrome-extension://{bare}/");
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        } else if (id.contains('@') || (id.starts_with('{') && id.ends_with('}')))
            && !id.contains(['\'', '"', '\n'])
        {
            if !firefox.iter().any(|f| f == id) {
                firefox.push(id.to_owned());
            }
        } else {
            return Err(usage(format!(
                "{id:?} is neither a Chromium extension ID (32 letters a-p) nor a Firefox add-on ID"
            )));
        }
    }
    Ok((origins, firefox))
}

#[derive(Serialize)]
struct Report {
    host: Option<String>,
    wrapper: Option<String>,
    manifests: Vec<Written>,
    /// Chromium browsers left out: no Chromium extension was allowed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<&'static str>,
}

const NO_CHROMIUM_ID: &str = "no Chromium extension to allow: pass --extension-id ID (the store build) or --dev (the development build you load unpacked)";

#[derive(Serialize)]
struct Written {
    browser: &'static str,
    path: String,
}

pub(crate) async fn extension_cmd(ctx: &mut Ctx, cmd: ExtensionCommand) -> CliResult<()> {
    match cmd {
        ExtensionCommand::InstallHost(args) => install(ctx, &args),
        ExtensionCommand::UninstallHost(args) => uninstall(ctx, &args),
        ExtensionCommand::HostStatus(args) => host_status(ctx, &args),
    }
}

#[derive(Serialize)]
struct StatusReport {
    /// This `KLAV_HOME`'s wrapper.
    wrapper: String,
    /// The host it runs, if it exists.
    wrapper_host: Option<String>,
    /// The host it should run (`--host`, or the one `install-host` would
    /// pick), if found.
    host: Option<String>,
    manifests: Vec<ManifestState>,
}

#[derive(Serialize)]
struct ManifestState {
    browser: &'static str,
    path: String,
    exists: bool,
    /// The manifest's `path`.
    points_to: Option<String>,
    /// What that runs: the host a wrapper `exec`s, or `points_to` itself.
    runs: Option<String>,
    /// Points to this home's wrapper, the wrapper runs `host`, and that
    /// host lets in every extension the manifest lists.
    current: bool,
    /// Extensions the manifest lists that its host would refuse: the
    /// wrapper's `--allow` list and the host's defaults leave them out.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    refused: Vec<String>,
    /// Why it is not current when its host would refuse one, with the
    /// command that fixes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Points to this home's wrapper, which runs `host` (`current` but
    /// for `refused`).
    #[serde(skip)]
    ours: bool,
}

/// The rest of a wrapper's `exec` line.
fn exec_line(script: &str) -> Option<&str> {
    script
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("exec "))
        .map(str::trim_start)
}

/// `line` split into words as `sh` would, for what `install-host` writes:
/// single quotes (with `'\''`), double quotes (`"$@"`) and `\`, without
/// expansions. `None` with a quote left open.
fn sh_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => words.extend(word.take()),
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => w.push(c),
                    }
                }
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => w.push(chars.next()?),
                        c => w.push(c),
                    }
                }
            }
            '\\' => word.get_or_insert_with(String::new).push(chars.next()?),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    Some(words)
}

/// The program a wrapper written by `install-host` runs: the first word
/// after `exec`, single-quoted.
fn wrapper_target(script: &str) -> Option<String> {
    let line = exec_line(script)?;
    if !line.starts_with('\'') {
        return None;
    }
    sh_words(line)?.into_iter().next()
}

/// What a manifest's `path` runs and the extensions it passes with
/// `--allow`, read as `klav-native-host`'s `parse_args` reads them. A
/// program run directly gets none.
fn host_command(points_to: &Path) -> Option<(PathBuf, Vec<String>)> {
    let bytes = std::fs::read(points_to).ok()?;
    if !bytes.starts_with(b"#!") {
        return Some((points_to.to_path_buf(), Vec::new()));
    }
    let words = sh_words(exec_line(&String::from_utf8_lossy(&bytes))?)?;
    let (program, args) = words.split_first()?;
    let mut allowed = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--allow" => allowed.extend(it.next().cloned()),
            "--home" => {
                it.next();
            }
            _ => {}
        }
    }
    Some((PathBuf::from(program), allowed))
}

/// The extensions `manifest` lists (`allowed_origins`, `allowed_extensions`)
/// that the host it points to would refuse. Empty when that cannot be told:
/// a program other than `klav-native-host`, or a wrapper it cannot read.
fn refused_by_host(manifest: &serde_json::Value, points_to: &Path) -> Vec<Caller> {
    let Some((program, allowed)) = host_command(points_to) else {
        return Vec::new();
    };
    if program.file_name() != Some(std::ffi::OsStr::new(&host_file_name())) {
        return Vec::new();
    }
    let listed = |key: &str| {
        manifest
            .get(key)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    listed("allowed_origins")
        .map(Caller::Chromium)
        .chain(listed("allowed_extensions").map(Caller::Firefox))
        .filter(|caller| !caller_allowed(caller, &allowed))
        .collect()
}

/// What a manifest's `path` runs.
fn runs(points_to: &Path) -> Option<String> {
    match std::fs::read(points_to) {
        Ok(bytes) if bytes.starts_with(b"#!") => wrapper_target(&String::from_utf8_lossy(&bytes))
            .or_else(|| Some(points_to.display().to_string())),
        Ok(_) => Some(points_to.display().to_string()),
        Err(_) => None,
    }
}

fn host_status(ctx: &Ctx, args: &HostArgs) -> CliResult<()> {
    let host = host_binary(args.host.as_deref())
        .ok()
        .map(|p| p.display().to_string());
    let wrapper = ctx.home.file("native-host").join("klav-native-host");
    let wrapper_host = std::fs::read_to_string(&wrapper)
        .ok()
        .and_then(|script| wrapper_target(&script));
    let ours = wrapper_host.is_some() && wrapper_host == host;
    let mut report = StatusReport {
        wrapper: wrapper.display().to_string(),
        wrapper_host,
        host,
        manifests: Vec::new(),
    };
    for Target { browser, path, .. } in targets(args)? {
        let manifest = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
        let points_to = manifest
            .as_ref()
            .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(str::to_owned));
        let refused = match (&manifest, &points_to) {
            (Some(manifest), Some(points_to)) => refused_by_host(manifest, Path::new(points_to)),
            _ => Vec::new(),
        };
        let reason = (!refused.is_empty()).then(|| {
            let each: Vec<String> = refused
                .iter()
                .map(|caller| format!("{} (`{}`)", caller.id(), install_hint(caller)))
                .collect();
            format!(
                "its host would refuse what this manifest lets in: {}",
                each.join(", ")
            )
        });
        let ours = ours && points_to.as_deref().map(Path::new) == Some(wrapper.as_path());
        report.manifests.push(ManifestState {
            browser: browser_name(browser),
            path: path.display().to_string(),
            exists: path.is_file(),
            runs: points_to.as_deref().map(Path::new).and_then(runs),
            points_to,
            current: ours && refused.is_empty(),
            refused: refused.iter().map(|c| c.id().to_owned()).collect(),
            reason,
            ours,
        });
    }
    if args.json.json {
        return output::json(&report);
    }
    if report.manifests.is_empty() {
        output::info("No supported browser found.");
    }
    for m in &report.manifests {
        let mut state = if m.ours {
            "this KLAV_HOME".to_owned()
        } else if !m.exists {
            "no manifest".to_owned()
        } else {
            format!(
                "other: {}",
                m.runs.as_deref().or(m.points_to.as_deref()).unwrap_or("?")
            )
        };
        if let Some(reason) = &m.reason {
            state.push_str(", but ");
            state.push_str(reason);
        }
        output::info(&format!("  {:<9} {state}  ({})", m.browser, m.path));
    }
    Ok(())
}

fn install(ctx: &Ctx, args: &HostArgs) -> CliResult<()> {
    let host = host_binary(args.host.as_deref())?;
    let (origins, firefox) = allowed(&args.extension_id, args.dev)?;
    let mut targets = targets(args)?;
    // A Chromium manifest needs an extension to allow. Named browsers
    // without one are an error; found ones are left out with a note.
    let mut skipped = Vec::new();
    if origins.is_empty() {
        let named = !args.browser.is_empty() || args.user_data_dir.is_some();
        // Only Chromium's format (`allowed_origins`) needs one: Firefox's
        // (also Dia's copy in Mozilla's directory) lists add-on IDs.
        if named && targets.iter().any(|t| !t.firefox) {
            return Err(usage(NO_CHROMIUM_ID));
        }
        targets.retain(|t| {
            if !t.firefox {
                skipped.push(browser_name(t.browser));
            }
            t.firefox
        });
        if targets.is_empty() && !skipped.is_empty() {
            return Err(usage(NO_CHROMIUM_ID));
        }
    }
    if targets.is_empty() {
        return Err(usage(
            "no supported browser found: name one with --browser, or give --user-data-dir",
        ));
    }
    ctx.home.ensure()?;
    let dir = ctx.home.file("native-host");
    std::fs::create_dir_all(&dir)?;
    klav_client::home::set_mode(&dir, 0o700)?;
    let wrapper = dir.join("klav-native-host");
    let mut script = String::from(
        "#!/bin/sh\n# Klav native messaging host for this KLAV_HOME.\n# Written by `klav extension install-host`; run it again to update.\nexec ",
    );
    script.push_str(&sh_quote(&host.to_string_lossy()));
    script.push_str(" --home ");
    script.push_str(&sh_quote(&ctx.home.dir().to_string_lossy()));
    // The host already allows its defaults (the store builds and Firefox's
    // add-on); everything else goes in, the development build too.
    let defaults = default_allowed();
    for id in origins
        .iter()
        .chain(firefox.iter())
        .filter(|id| !defaults.contains(id))
    {
        script.push_str(" --allow ");
        script.push_str(&sh_quote(id));
    }
    script.push_str(" \"$@\"\n");
    std::fs::write(&wrapper, script)?;
    klav_client::home::set_mode(&wrapper, 0o700)?;
    let mut report = Report {
        host: Some(host.display().to_string()),
        wrapper: Some(wrapper.display().to_string()),
        manifests: Vec::new(),
        skipped,
    };
    for Target {
        browser,
        path,
        firefox: firefox_format,
    } in targets
    {
        let manifest = if firefox_format {
            serde_json::json!({
                "name": HOST_NAME,
                "description": "Klav: bridge between the browser extension and klavd",
                "path": wrapper,
                "type": "stdio",
                "allowed_extensions": firefox,
            })
        } else {
            serde_json::json!({
                "name": HOST_NAME,
                "description": "Klav: bridge between the browser extension and klavd",
                "path": wrapper,
                "type": "stdio",
                "allowed_origins": origins,
            })
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::Other(format!("{}: {e}", parent.display())))?;
        }
        let mut text =
            serde_json::to_string_pretty(&manifest).map_err(|e| CliError::Other(e.to_string()))?;
        text.push('\n');
        std::fs::write(&path, text)
            .map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?;
        report.manifests.push(Written {
            browser: browser_name(browser),
            path: path.display().to_string(),
        });
    }
    if args.json.json {
        return output::json(&report);
    }
    output::info(&format!(
        "Native messaging host: {} (for KLAV_HOME {})",
        wrapper.display(),
        ctx.home.dir().display()
    ));
    for m in &report.manifests {
        output::info(&format!("  {:<9} {}", m.browser, m.path));
    }
    if !report.skipped.is_empty() {
        output::info(&format!(
            "Skipped {}: {NO_CHROMIUM_ID}.",
            report.skipped.join(", ")
        ));
    }
    output::info("Restart the browser if the extension was already open.");
    Ok(())
}

fn uninstall(ctx: &Ctx, args: &HostArgs) -> CliResult<()> {
    let mut report = Report {
        host: None,
        wrapper: None,
        manifests: Vec::new(),
        skipped: Vec::new(),
    };
    for Target { browser, path, .. } in targets(args)? {
        // Mozilla's manifest is Firefox's too: `uninstall-host --browser dia`
        // leaves it unless Firefox goes as well.
        if browser == Browser::Dia
            && path.components().any(|c| c.as_os_str() == "Mozilla")
            && !args.browser.is_empty()
            && !args.browser.contains(&Browser::Firefox)
        {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => report.manifests.push(Written {
                browser: browser_name(browser),
                path: path.display().to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CliError::Other(format!("{}: {e}", path.display()))),
        }
    }
    // The wrapper serves every browser: remove it only with all of them.
    if args.browser.is_empty() && args.user_data_dir.is_none() {
        let wrapper = ctx.home.file("native-host").join("klav-native-host");
        if std::fs::remove_file(&wrapper).is_ok() {
            report.wrapper = Some(wrapper.display().to_string());
        }
    }
    if args.json.json {
        return output::json(&report);
    }
    if report.manifests.is_empty() {
        output::info("No native messaging host manifests to remove.");
    }
    for m in &report.manifests {
        output::info(&format!("Removed {:<9} {}", m.browser, m.path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use klav_daemon::native::{FIREFOX_ID, STORE_CHROMIUM_IDS};

    use super::*;

    #[test]
    fn extension_ids_are_sorted_by_browser() {
        let ids: [String; 3] = [
            "abcdefghijklmnopabcdefghijklmnop".into(),
            "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/".into(),
            "store@klav.dev".into(),
        ];
        let stores = STORE_CHROMIUM_IDS.len();
        let (origins, firefox) = allowed(&ids, false).unwrap();
        // The development build's ID (whose key is public) only with --dev.
        assert_eq!(origins.len(), stores + 2);
        assert!(!origins.iter().any(|o| o.contains(DEV_CHROMIUM_ID)));
        // The store builds go into every Chromium manifest, without --dev.
        for (origin, id) in origins.iter().zip(STORE_CHROMIUM_IDS) {
            assert_eq!(*origin, format!("chrome-extension://{id}/"));
        }
        assert!(origins[stores].ends_with("abcdefghijklmnopabcdefghijklmnop/"));
        assert_eq!(
            firefox,
            vec![FIREFOX_ID.to_owned(), "store@klav.dev".into()]
        );
        let (origins, _) = allowed(&ids, true).unwrap();
        assert_eq!(origins.len(), stores + 3);
        assert_eq!(origins[0], format!("chrome-extension://{DEV_CHROMIUM_ID}/"));
        assert_eq!(allowed(&[], false).unwrap().0.len(), stores);
        assert!(allowed(&["not an id".into()], false).is_err());
        assert!(allowed(&["x'@y".into()], false).is_err());
    }

    #[test]
    fn shell_quoting_survives_quotes() {
        assert_eq!(sh_quote("/a b/it's"), r"'/a b/it'\''s'");
    }

    #[test]
    fn the_wrapper_names_its_host() {
        let host = "/Applications/Klav.app/Contents/Helpers/it's here/klav-native-host";
        let script = format!(
            "#!/bin/sh\n# Klav native messaging host\nexec {} --home {} \"$@\"\n",
            sh_quote(host),
            sh_quote("/Users/a/Library/Application Support/klav")
        );
        assert_eq!(wrapper_target(&script).as_deref(), Some(host));
        assert_eq!(wrapper_target("#!/bin/sh\necho hi\n"), None);
        assert_eq!(wrapper_target("#!/bin/sh\nexec /bin/true\n"), None);
    }

    #[test]
    fn the_wrapper_line_splits_as_sh_does() {
        let dev = format!("chrome-extension://{DEV_CHROMIUM_ID}/");
        // As `install` writes it.
        let line = format!(
            "{} --home {} --allow {} --allow {} \"$@\"",
            sh_quote("/a b/it's/klav-native-host"),
            sh_quote("/Users/a/Library/Application Support/klav"),
            sh_quote(&dev),
            sh_quote("store@klav.dev"),
        );
        assert_eq!(
            sh_words(&line).unwrap(),
            vec![
                "/a b/it's/klav-native-host",
                "--home",
                "/Users/a/Library/Application Support/klav",
                "--allow",
                dev.as_str(),
                "--allow",
                "store@klav.dev",
                "$@",
            ]
        );
        assert_eq!(
            sh_words(r#"a\ b "c d" e'f'"#).unwrap(),
            vec!["a b", "c d", "ef"]
        );
        // A quote left open: nothing to go on.
        assert_eq!(sh_words("'/bin/host --allow x"), None);
        assert_eq!(sh_words("x \"y"), None);
    }
}
