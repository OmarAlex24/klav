//! A headless Chrome driven over CDP and a tiny login site, for the tests
//! of `fill`.
//!
//! Chrome is looked up in `KLAV_TEST_CHROME`, then on the `PATH`, then in
//! the usual install places and the Playwright cache. Without one the
//! browser tests are skipped, except on CI (`CI` set), where they fail.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use klav_sdk::cdp::Cdp;
use serde_json::{Value, json};

fn playwright_caches() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let mut roots = vec![
        home.join("Library/Caches/ms-playwright"),
        home.join(".cache/ms-playwright"),
    ];
    if let Some(p) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        roots.insert(0, PathBuf::from(p));
    }
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("chromium-"))
            })
            .collect();
        dirs.sort();
        for dir in dirs.into_iter().rev() {
            for candidate in [
                "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                "chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
                "chrome-linux64/chrome",
                "chrome-linux/chrome",
            ] {
                found.push(dir.join(candidate));
            }
        }
    }
    found
}

/// A Chrome or Chromium binary, if there is one.
pub fn find_chrome() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KLAV_TEST_CHROME") {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for name in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "chrome",
        ] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let mut fixed = vec![
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ];
    fixed.extend(playwright_caches());
    fixed.into_iter().find(|p| p.is_file())
}

/// Chrome, or `None` (skip) when not on CI.
pub fn chrome_or_skip(test: &str) -> Option<PathBuf> {
    match find_chrome() {
        Some(p) => Some(p),
        None if std::env::var_os("CI").is_some() => {
            panic!("{test}: no Chrome found on CI (set KLAV_TEST_CHROME)")
        }
        None => {
            eprintln!("{test}: skipped, no Chrome found (set KLAV_TEST_CHROME)");
            None
        }
    }
}

/// How long Chrome may take to write its DevTools port.
const START_WAIT: Duration = Duration::from_secs(60);
/// How long a page may take to show the title a test waits for. CI runners
/// build and run several test binaries at once; a quick page returns at
/// once, so a long wait only costs time when something is wrong.
const PAGE_WAIT: Duration = Duration::from_secs(60);
/// While the site's page has not loaded, Chrome is told to navigate to it
/// again this often.
const NAVIGATE_EVERY: Duration = Duration::from_secs(10);
/// How long the site waits for a request on a connection Chrome opened.
const READ_WAIT: Duration = Duration::from_secs(30);
/// The title of the site's login page.
const LOGIN_TITLE: &str = "Login";

/// A headless Chrome with remote debugging on a random port.
pub struct Chrome {
    child: Child,
    /// Holds the profile (`profile/`) and Chrome's stderr (`stderr.log`).
    dir: tempfile::TempDir,
    /// `http://127.0.0.1:<port>`.
    pub endpoint: String,
}

impl Chrome {
    /// Launches Chrome on `url`, a page of `site`, and returns once it shows
    /// the login page. That page is then the browser's only page: the one
    /// [`evaluate`] and `klav agent fill` use. If it does not load, panics
    /// with what Chrome and the site saw.
    pub async fn launch(binary: &Path, site: &LoginSite, url: &str) -> Self {
        let mut chrome = Self::start(binary, url);
        chrome.open(site, url).await;
        chrome
    }

    fn start(binary: &Path, url: &str) -> Self {
        let dir = tempfile::tempdir().expect("chrome dir");
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).expect("profile");
        let stderr = std::fs::File::create(dir.path().join("stderr.log")).expect("chrome log");
        let mut cmd = Command::new(binary);
        cmd.args([
            "--headless=new",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-extensions",
            "--password-store=basic",
            "--use-mock-keychain",
        ])
        .arg(format!("--user-data-dir={}", profile.display()));
        if cfg!(target_os = "linux") {
            // CI runners do not allow Chrome's user-namespace sandbox.
            cmd.arg("--no-sandbox");
        }
        let child = cmd
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("launch chrome");
        // Built before waiting, so that a panic below still kills Chrome.
        let mut chrome = Self {
            child,
            dir,
            endpoint: String::new(),
        };
        let port_file = profile.join("DevToolsActivePort");
        let deadline = Instant::now() + START_WAIT;
        let port = loop {
            if let Ok(text) = std::fs::read_to_string(&port_file)
                && let Some(port) = text
                    .lines()
                    .next()
                    .and_then(|l| l.trim().parse::<u16>().ok())
            {
                break port;
            }
            if let Ok(Some(status)) = chrome.child.try_wait() {
                panic!(
                    "chrome exited before listening ({status})\n{}",
                    chrome.stderr_tail()
                );
            }
            assert!(
                Instant::now() < deadline,
                "chrome did not start within {START_WAIT:?}\n{}",
                chrome.stderr_tail()
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        chrome.endpoint = format!("http://127.0.0.1:{port}");
        chrome
    }

    /// Waits until a page of `site` shows the login page and closes the
    /// other pages. A page that has not loaded it is navigated to `url`
    /// again every [`NAVIGATE_EVERY`].
    async fn open(&mut self, site: &LoginSite, url: &str) {
        let start = Instant::now();
        let mut navigate_at = start + NAVIGATE_EVERY;
        let mut navigations = 0;
        let mut last_error = None;
        while start.elapsed() < PAGE_WAIT {
            let navigate = Instant::now() >= navigate_at;
            match open_step(&self.endpoint, &site.origin, url, navigate).await {
                Ok(Step::Loaded) => return,
                Ok(Step::Waiting) => {}
                Ok(Step::Navigated) => {
                    navigations += 1;
                    navigate_at = Instant::now() + NAVIGATE_EVERY;
                }
                Err(e) => last_error = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let state = match self.child.try_wait() {
            Ok(Some(status)) => format!("exited ({status})"),
            Ok(None) => "running".to_owned(),
            Err(e) => format!("unknown ({e})"),
        };
        panic!(
            "the page did not load: {} did not show {LOGIN_TITLE:?} within {PAGE_WAIT:?} \
             ({navigations} extra navigations)\n\
             targets:\n{}\n\
             site: {}\n\
             chrome: {state}\n\
             last CDP error: {}\n\
             chrome stderr (last lines):\n{}",
            redact(url),
            describe_targets(&self.endpoint).await,
            site.traffic(),
            last_error.as_deref().unwrap_or("none"),
            self.stderr_tail(),
        );
    }

    /// The last lines Chrome wrote to stderr, for a failure message. Only
    /// read before anything is typed into the browser.
    fn stderr_tail(&self) -> String {
        let text = std::fs::read(self.dir.path().join("stderr.log")).unwrap_or_default();
        let text = String::from_utf8_lossy(&text);
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines[lines.len().saturating_sub(20)..].join("\n");
        if tail.is_empty() {
            "  (empty)".to_owned()
        } else {
            tail
        }
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What one look at the browser found.
enum Step {
    /// A page of the site shows the login page, and it is the only page.
    Loaded,
    /// Not yet.
    Waiting,
    /// Not yet, and a page was told to navigate to the site.
    Navigated,
}

async fn open_step(endpoint: &str, origin: &str, url: &str, navigate: bool) -> CdpResult<Step> {
    let mut cdp = Cdp::connect(endpoint).await.map_err(|e| e.to_string())?;
    let step = open_step_on(&mut cdp, origin, url, navigate).await;
    cdp.close().await;
    step
}

async fn open_step_on(cdp: &mut Cdp, origin: &str, url: &str, navigate: bool) -> CdpResult<Step> {
    let pages = pages(cdp).await?;
    let site_page = pages.iter().find(|(_, u)| u.starts_with(origin));
    if let Some((page, _)) = site_page {
        let session = attach(cdp, page).await?;
        if evaluate_on(cdp, &session, "document.title").await? == LOGIN_TITLE {
            // `evaluate` and `klav agent fill` take the first page: leave
            // only this one.
            for (other, _) in pages.iter().filter(|(other, _)| other != page) {
                call(
                    cdp,
                    None,
                    "Target.closeTarget",
                    json!({ "targetId": other }),
                )
                .await?;
            }
            // A page navigated to over CDP leaves the keyboard focus where
            // it was (the address bar of a tab opened on another page), and
            // `fill` only types into a focused input.
            call(cdp, Some(&session), "Page.bringToFront", json!({})).await?;
            return Ok(Step::Loaded);
        }
    }
    if !navigate {
        return Ok(Step::Waiting);
    }
    match site_page.or(pages.first()) {
        Some((page, _)) => {
            let session = attach(cdp, page).await?;
            let out = call(cdp, Some(&session), "Page.navigate", json!({ "url": url })).await?;
            if let Some(error) = out["errorText"].as_str() {
                return Err(format!("Page.navigate: {error}"));
            }
        }
        None => {
            call(cdp, None, "Target.createTarget", json!({ "url": url })).await?;
        }
    }
    Ok(Step::Navigated)
}

/// A login page on 127.0.0.1 that records the credentials it receives.
pub struct LoginSite {
    pub url: String,
    /// The bodies of the forms sent to `/session`. They hold the password:
    /// never print them.
    pub received: Arc<Mutex<Vec<String>>>,
    /// `http://127.0.0.1:<port>/`, how every address of the site starts.
    origin: String,
    traffic: Arc<Mutex<Traffic>>,
}

/// What reached the site, for failure messages. No bodies, no queries.
#[derive(Default)]
struct Traffic {
    connections: usize,
    /// `METHOD /path` of each request.
    requests: Vec<String>,
    /// Connections closed, or silent for [`READ_WAIT`], before a request.
    silent: usize,
}

const PAGE: &str = "<!doctype html><title>Login</title>\
<form method=post action=/session>\
<input id=user name=username autocomplete=username>\
<input id=pass name=password type=password>\
<button>Sign in</button></form>";

impl LoginSite {
    pub fn start(password: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let traffic = Arc::new(Mutex::new(Traffic::default()));
        let (log, seen) = (received.clone(), traffic.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                seen.lock().expect("lock").connections += 1;
                let (log, seen) = (log.clone(), seen.clone());
                // One thread per connection: Chrome opens spare connections
                // that may stay silent, and a request must not wait behind
                // them.
                std::thread::spawn(move || serve(stream, password, &log, &seen));
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}/login"),
            received,
            origin: format!("http://127.0.0.1:{port}/"),
            traffic,
        }
    }

    /// What reached the site so far: connections and request lines.
    pub fn traffic(&self) -> String {
        let t = self.traffic.lock().expect("lock");
        let waiting = t
            .connections
            .saturating_sub(t.silent)
            .saturating_sub(t.requests.len());
        let requests = if t.requests.is_empty() {
            "none".to_owned()
        } else {
            t.requests.join(", ")
        };
        format!(
            "{} connections ({} closed or silent before a request, {waiting} still open without one); requests: {requests}",
            t.connections, t.silent
        )
    }
}

fn serve(stream: TcpStream, password: &str, log: &Mutex<Vec<String>>, seen: &Mutex<Traffic>) {
    let _ = stream.set_read_timeout(Some(READ_WAIT));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut stream = stream;
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        seen.lock().expect("lock").silent += 1;
        return;
    }
    let request: Vec<&str> = request_line
        .split_whitespace()
        .take(2)
        .map(redact)
        .collect();
    seen.lock().expect("lock").requests.push(request.join(" "));
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; length];
    let _ = reader.read_exact(&mut body);
    let body = String::from_utf8_lossy(&body).into_owned();
    let page = if request_line.starts_with("POST /session") {
        let ok = body.contains("username=ana") && body.contains(&format!("password={password}"));
        log.lock().expect("lock").push(body);
        if ok {
            "<title>Welcome</title>Welcome ana"
        } else {
            "<title>Nope</title>Wrong"
        }
    } else {
        PAGE
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
}

/// Errors of the CDP helpers, as text for failure messages.
type CdpResult<T> = Result<T, String>;

async fn call(
    cdp: &mut Cdp,
    session: Option<&str>,
    method: &str,
    params: Value,
) -> CdpResult<Value> {
    cdp.call(session, method, params)
        .await
        .map_err(|e| format!("{method}: {e}"))
}

/// The page targets, in the browser's order: `(id, url)`.
async fn pages(cdp: &mut Cdp) -> CdpResult<Vec<(String, String)>> {
    let targets = call(cdp, None, "Target.getTargets", json!({})).await?;
    Ok(targets["targetInfos"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t["type"] == "page")
        .filter_map(|t| {
            let id = t["targetId"].as_str()?;
            Some((
                id.to_owned(),
                t["url"].as_str().unwrap_or_default().to_owned(),
            ))
        })
        .collect())
}

async fn attach(cdp: &mut Cdp, target: &str) -> CdpResult<String> {
    let attached = call(
        cdp,
        None,
        "Target.attachToTarget",
        json!({ "targetId": target, "flatten": true }),
    )
    .await?;
    attached["sessionId"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "Target.attachToTarget: no session".to_owned())
}

async fn evaluate_in(cdp: &mut Cdp, target: &str, script: &str) -> CdpResult<Value> {
    let session = attach(cdp, target).await?;
    evaluate_on(cdp, &session, script).await
}

async fn evaluate_on(cdp: &mut Cdp, session: &str, script: &str) -> CdpResult<Value> {
    let out = call(
        cdp,
        Some(session),
        "Runtime.evaluate",
        json!({ "expression": script, "returnByValue": true, "awaitPromise": true }),
    )
    .await?;
    Ok(out["result"]["value"].clone())
}

async fn try_evaluate(endpoint: &str, script: &str) -> CdpResult<Value> {
    let mut cdp = Cdp::connect(endpoint).await.map_err(|e| e.to_string())?;
    let out = match pages(&mut cdp).await {
        Ok(pages) => match pages.first() {
            Some((page, _)) => evaluate_in(&mut cdp, page, script).await,
            None => Err("no page in the browser".to_owned()),
        },
        Err(e) => Err(e),
    };
    cdp.close().await;
    out
}

/// Runs a script in the first page of the browser (test side only): the
/// page `klav agent fill` picks too, which [`Chrome::launch`] leaves as the
/// site's only page.
pub async fn evaluate(endpoint: &str, script: &str) -> Value {
    try_evaluate(endpoint, script)
        .await
        .unwrap_or_else(|e| panic!("evaluate in the page: {e}"))
}

/// Waits until the page's title is `title`. On a timeout it prints the
/// targets, which show up with the failing test's output.
pub async fn wait_title(endpoint: &str, title: &str) -> bool {
    let deadline = Instant::now() + PAGE_WAIT;
    while Instant::now() < deadline {
        // An error (a page between two documents) means "not yet".
        if try_evaluate(endpoint, "document.title")
            .await
            .is_ok_and(|t| t == title)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!(
        "wait_title({title:?}): not shown within {PAGE_WAIT:?}; targets:\n{}",
        describe_targets(endpoint).await
    );
    false
}

/// Every target's type, address and title, one per line. Queries and
/// fragments are cut: an address may carry tokens.
async fn describe_targets(endpoint: &str) -> String {
    let mut cdp = match Cdp::connect(endpoint).await {
        Ok(cdp) => cdp,
        Err(e) => return format!("  (cannot connect: {e})"),
    };
    let out = match call(&mut cdp, None, "Target.getTargets", json!({})).await {
        Ok(targets) => {
            let lines: Vec<String> = targets["targetInfos"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| {
                    let field =
                        |name: &str| redact(t[name].as_str().unwrap_or_default()).to_owned();
                    format!("  {} {} {:?}", field("type"), field("url"), field("title"))
                })
                .collect();
            if lines.is_empty() {
                "  (none)".to_owned()
            } else {
                lines.join("\n")
            }
        }
        Err(e) => format!("  ({e})"),
    };
    cdp.close().await;
    out
}

/// `text` up to its first `?` or `#`.
fn redact(text: &str) -> &str {
    text.split(['?', '#']).next().unwrap_or_default()
}
