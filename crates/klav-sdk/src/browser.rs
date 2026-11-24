//! `fill`: types a login or a card into a browser page over CDP, without
//! returning the values (design §5.4, ADR 0014 §9).
//!
//! Before typing, the page's address is checked against the item's URLs
//! (threat T21) and sent to the server as the `domain` claim, so a policy
//! that limits `fill` to some domains is enforced on both sides. The
//! address is checked again right before each field.
//!
//! A runtime can register a browser as a named session (`sdk:<name>`), so
//! `klav mcp` can fill into it without seeing the page itself. The target
//! `extension` fills the active tab of the person's browser through
//! `klavd` and Klav's extension (ADR 0017): the agent checks the tab's
//! address and decrypts the values under its own grant, and the extension
//! types them only if the tab is still on that host, telling the person.

use std::path::PathBuf;
use std::time::Duration;

use klav_client::{ClientError, ClientResult, Home};
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::model::{Item, SecretValue};
use klav_core::policy::Permission;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cdp::{Cdp, is_loopback};
use crate::session::{Session, field_value, totp_code};

/// A page to fill: a browser's CDP endpoint and, optionally, the target
/// (tab) ID; without it, the first page tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTarget {
    /// `http://127.0.0.1:9222` or a `ws://…/devtools/browser/…` URL.
    pub endpoint: String,
    /// CDP target ID of the tab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

/// What was filled. Addresses are origins only ([`klav_core::site::origin`]):
/// a page's path, query and fragment may carry tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillReport {
    /// The page's origin when filling.
    pub url: String,
    /// Fields typed (names, never values).
    pub filled: Vec<String>,
    /// The form was submitted ([`FillOptions::submit`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub submitted: bool,
    /// After submitting: whether a new page loaded within
    /// [`SUBMIT_WAIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub navigated: Option<bool>,
    /// After submitting: the page's origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_after: Option<String>,
    /// For the person (an older `klavd`, say). Never a value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl FillReport {
    /// The same report with its addresses cut to their origin (what
    /// `klavd` and the extension answer is not trusted to be cut).
    fn trimmed(mut self) -> Self {
        self.url = origin(&self.url);
        self.url_after = self.url_after.as_deref().map(origin);
        self
    }
}

/// How to fill.
#[derive(Debug, Clone, Copy, Default)]
pub struct FillOptions<'a> {
    /// CSS selectors for fields (default: the usual login and card inputs).
    pub selectors: &'a [FieldSelector],
    /// Submit the form after filling: the form of the last field typed
    /// (`requestSubmit()`), only if it sends to the page's own origin, or
    /// else a submit button outside any form. Off by default: the caller
    /// usually checks the page first.
    pub submit: bool,
    /// Type the current one-time code of a TOTP field: uses the `totp`
    /// permission instead of `fill`, and the field must be a one-time
    /// password field (MCP `get_totp` with a target).
    pub totp: bool,
}

/// How long to wait for a new page after submitting.
pub const SUBMIT_WAIT: Duration = Duration::from_secs(10);

/// Where a field goes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSelector {
    /// Field name in the item (`username`, `password`, `totp`, `number`…).
    pub field: String,
    /// CSS selector of the input.
    pub selector: String,
}

const USERNAME: &str = "input[autocomplete~='username'], input[type='email'], \
     input[name*='user' i], input[id*='user' i], input[name*='email' i], input[id*='email' i], \
     input[name*='login' i], input[id*='login' i]";
const PASSWORD: &str = "input[type='password']";
const ONE_TIME: &str = "input[autocomplete='one-time-code'], input[name*='otp' i], \
     input[id*='otp' i], input[name*='totp' i], input[id*='totp' i]";

/// The default selector for a field of an item.
fn default_selector(kind: ItemKind, field: &str, field_kind: FieldKind) -> Option<&'static str> {
    match (kind, field, field_kind) {
        (_, _, FieldKind::Username) | (ItemKind::Login, "username", _) => Some(USERNAME),
        (_, _, FieldKind::Password) => Some(PASSWORD),
        (_, _, FieldKind::Totp) => Some(ONE_TIME),
        (ItemKind::Card, "cardholder", _) => Some("input[autocomplete='cc-name']"),
        (ItemKind::Card, "number", _) => Some("input[autocomplete='cc-number']"),
        (ItemKind::Card, "expiry", _) => Some("input[autocomplete='cc-exp']"),
        (ItemKind::Card, "cvv", _) => Some("input[autocomplete='cc-csc']"),
        _ => None,
    }
}

/// The page's host if `url` is a page Klav may fill: `https`, or `http`
/// on this machine (`klav_core::site`).
pub fn fillable_host(url: &str) -> ClientResult<String> {
    klav_core::site::fillable_host(url).map_err(|e| ClientError::Denied(e.to_string()))
}

pub use klav_core::site::{host_matches, origin, url_matches};

/// The site rule again, with the URLs of the version the server delivered
/// (the listed one may be older and list other sites), and only those the
/// person confirmed: a site an agent added waits for her (ADR 0030 §7).
fn check_delivered_urls(
    session: &Session,
    item_id: klav_core::ids::ItemId,
    item: &Item,
    url: &str,
    host: &str,
) -> ClientResult<()> {
    if item.kind() == ItemKind::Card {
        return Ok(());
    }
    if !url_matches(url, item.urls()) {
        return Err(ClientError::Denied(format!(
            "the current version of the item is not for {host}: Klav does not fill it (phishing protection)"
        )));
    }
    session.check_confirmed(item_id, host)
}

/// The fields to type: the one named in the reference, or the usual ones
/// of a login (username, password) or a card.
fn plan_names(item: &Item, field: Option<&str>) -> ClientResult<Vec<String>> {
    Ok(match field {
        Some(f) => vec![f.to_owned()],
        None => match item.kind() {
            ItemKind::Login => ["username", "password"]
                .iter()
                .filter(|n| item.field(n).is_some_and(|f| !f.is_empty()))
                .map(|n| (*n).to_owned())
                .collect(),
            ItemKind::Card => ["cardholder", "number", "expiry", "cvv"]
                .iter()
                .filter(|n| item.field(n).is_some_and(|f| !f.is_empty()))
                .map(|n| (*n).to_owned())
                .collect(),
            other => {
                return Err(ClientError::Invalid(format!(
                    "say which field of this {other:?} item to fill (…/field)"
                )));
            }
        },
    })
}

/// [`plan_names`] with the CSS selector of each field.
fn plan(
    item: &Item,
    field: Option<&str>,
    selectors: &[FieldSelector],
) -> ClientResult<Vec<(String, String)>> {
    plan_names(item, field)?
        .into_iter()
        .map(|name| {
            let f = item
                .field(&name)
                .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?;
            let selector = selectors
                .iter()
                .find(|s| s.field == name)
                .map(|s| s.selector.clone())
                .or_else(|| default_selector(item.kind(), &name, f.kind()).map(str::to_owned))
                .ok_or_else(|| {
                    ClientError::Invalid(format!("give a CSS selector for the field {name:?}"))
                })?;
            Ok((name, selector))
        })
        .collect()
}

/// The text to type for a field: TOTP codes are computed; card expiry
/// dates (`2027-09`) become `09/27`.
fn text_for(item: &Item, name: &str) -> ClientResult<SecretValue> {
    let f = item
        .field(name)
        .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?;
    match (f.kind(), f.value()) {
        (FieldKind::Totp, _) => Ok(totp_code(item, Some(name))?.0),
        (FieldKind::MonthYear, FieldValue::Plain(v)) => {
            let (y, m) = v.split_once('-').unwrap_or((v, ""));
            Ok(SecretValue::new(format!("{m}/{}", y.get(2..).unwrap_or(y))))
        }
        _ => Ok(field_value(item, name)?.1),
    }
}

async fn page_url(cdp: &mut Cdp, target: &str) -> ClientResult<String> {
    let info = cdp
        .call(None, "Target.getTargetInfo", json!({ "targetId": target }))
        .await?;
    Ok(info["targetInfo"]["url"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

async fn pick_target(cdp: &mut Cdp, wanted: Option<&str>) -> ClientResult<String> {
    if let Some(t) = wanted {
        return Ok(t.to_owned());
    }
    let targets = cdp.call(None, "Target.getTargets", json!({})).await?;
    targets["targetInfos"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["type"] == "page")
        .and_then(|t| t["targetId"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| ClientError::NotFound("a page in the browser".into()))
}

/// What kind of input a value may go to. The caller (an LLM) chooses the
/// selectors, so the input is checked, not trusted: a password never goes
/// to a search box that the page reads as the user types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputRule {
    /// Only `input[type=password]`.
    Password,
    /// `input[type=password]`, or a text input that looks like a one-time
    /// code field ([`ONE_TIME`]).
    OneTime,
    /// A card field: a text, tel, number or password input.
    Card,
    /// Any visible text input or text area.
    Plain,
}

impl InputRule {
    fn of(item: ItemKind, kind: FieldKind) -> Self {
        match (item, kind) {
            (_, FieldKind::Password) => Self::Password,
            (_, FieldKind::Totp) => Self::OneTime,
            (ItemKind::Card, _) => Self::Card,
            (_, FieldKind::Concealed) => Self::Password,
            _ => Self::Plain,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::OneTime => "otp",
            Self::Card => "card",
            Self::Plain => "plain",
        }
    }
}

/// Checks the input is fit for the value (`rule`), focuses it and clears
/// it. Returns `'ok'` or why not.
const PREPARE: &str = "function(rule, oneTime) { \
    const isInput = this instanceof HTMLInputElement; \
    if (!isInput && !(this instanceof HTMLTextAreaElement)) { return 'it is not a text input'; } \
    const type = isInput ? (this.type || 'text').toLowerCase() : 'textarea'; \
    if (type === 'hidden' || this.disabled || this.readOnly) { return 'it is hidden or read-only'; } \
    const text = ['text', 'tel', 'number', 'textarea', ''].includes(type); \
    const fits = rule === 'password' ? type === 'password' \
        : rule === 'otp' ? type === 'password' || (isInput && text && this.matches(oneTime)) \
        : rule === 'card' ? type === 'password' || text \
        : !['search', 'url', 'file', 'checkbox', 'radio', 'submit', 'button', 'image', 'reset', 'range', 'color'].includes(type); \
    if (!fits) { return 'a ' + rule + ' value does not go into an input of type ' + type; } \
    this.focus(); if ('value' in this) { this.value = ''; } return 'ok'; }";

/// Whether the input has the focus of a focused document.
const FOCUSED: &str =
    "function() { return document.activeElement === this && document.hasFocus(); }";

/// Types `value` into the element matching `selector` (replacing what it
/// had), if it is fit for it (`rule`), right after checking it has the
/// focus and the page is still on `page_origin` (scheme, host and port).
#[allow(clippy::too_many_arguments)]
async fn type_into(
    cdp: &mut Cdp,
    session: &str,
    target_id: &str,
    page_origin: &str,
    selector: &str,
    rule: InputRule,
    value: &str,
) -> ClientResult<()> {
    let s = Some(session);
    let doc = cdp
        .call(s, "DOM.getDocument", json!({ "depth": 0 }))
        .await?;
    let root = doc["root"]["nodeId"].as_u64().unwrap_or(0);
    let found = cdp
        .call(
            s,
            "DOM.querySelector",
            json!({ "nodeId": root, "selector": selector }),
        )
        .await?;
    let node = found["nodeId"].as_u64().unwrap_or(0);
    if node == 0 {
        return Err(ClientError::NotFound(format!(
            "no input matches {selector:?} on the page"
        )));
    }
    let object = cdp
        .call(s, "DOM.resolveNode", json!({ "nodeId": node }))
        .await?;
    let object_id = object["object"]["objectId"]
        .as_str()
        .ok_or_else(|| ClientError::NotFound("the input".into()))?
        .to_owned();
    let prepared = cdp
        .call(
            s,
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": PREPARE,
                "arguments": [{ "value": rule.name() }, { "value": ONE_TIME }],
                "returnByValue": true,
            }),
        )
        .await?;
    match prepared["result"]["value"].as_str() {
        Some("ok") => {}
        why => {
            return Err(ClientError::Denied(format!(
                "Klav does not type into {selector:?}: {}",
                why.unwrap_or("the page did not answer")
            )));
        }
    }
    cdp.call(s, "DOM.focus", json!({ "nodeId": node })).await?;
    // Right before typing: the input still has the focus of a focused
    // page (a script could move it elsewhere), and the page is still on
    // the host that was checked.
    let focused = cdp
        .call(
            s,
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": FOCUSED,
                "returnByValue": true,
            }),
        )
        .await?;
    if focused["result"]["value"] != serde_json::Value::Bool(true) {
        return Err(ClientError::Denied(format!(
            "the input {selector:?} lost the focus before typing: stopped"
        )));
    }
    let now = page_url(cdp, target_id).await?;
    if origin(&now) != page_origin {
        return Err(ClientError::Denied(format!(
            "the page moved to {} while filling: stopped",
            origin(&now)
        )));
    }
    cdp.insert_text(session, value).await
}

/// Evaluates `expression` in the page and returns its value.
async fn evaluate(
    cdp: &mut Cdp,
    session: &str,
    expression: &str,
) -> ClientResult<serde_json::Value> {
    let out = cdp
        .call(
            Some(session),
            "Runtime.evaluate",
            json!({ "expression": expression, "returnByValue": true }),
        )
        .await?;
    Ok(out["result"]["value"].clone())
}

/// Marks the current document, so a new one (after the submit) is told
/// apart even when the address stays the same.
const MARK: &str = "window.__klavBeforeSubmit = true; true";
const MARKED: &str = "window.__klavBeforeSubmit === true";

/// Submits the form of the input at `selector` if it sends to the page's
/// own origin (or else a submit button outside any form) and waits up to
/// [`SUBMIT_WAIT`] for a new page. Returns whether one loaded and the
/// address then. Nothing typed is read back.
async fn submit(
    cdp: &mut Cdp,
    page: &str,
    target_id: &str,
    selector: &str,
) -> ClientResult<(bool, String)> {
    let before = page_url(cdp, target_id).await?;
    evaluate(cdp, page, MARK).await?;
    let selector = serde_json::to_string(selector)
        .map_err(|e| ClientError::Invalid(format!("selector: {e}")))?;
    let how = evaluate(
        cdp,
        page,
        &format!(
            "(() => {{ const el = document.querySelector({selector}); const form = el && el.form; \
             if (form) {{ \
               let to; try {{ to = new URL(form.action, location.href).origin; }} catch (e) {{ return 'elsewhere'; }} \
               if (to !== location.origin) {{ return 'elsewhere'; }} \
               if (form.requestSubmit) {{ form.requestSubmit(); }} else {{ form.submit(); }} return 'form'; }} \
             const button = Array.from(document.querySelectorAll(\"button[type=submit], input[type=submit]\")) \
               .find((b) => !b.form && !b.hasAttribute('formaction')); \
             if (button) {{ button.click(); return 'button'; }} return 'none'; }})()"
        ),
    )
    .await
    // A navigation that starts at once can end the call: the wait below
    // tells whether a new page loaded.
    .unwrap_or_else(|_| json!("form"));
    if how == "elsewhere" {
        return Err(ClientError::Denied(
            "the form sends to another site than the page: the fields were filled, not submitted"
                .into(),
        ));
    }
    if how == "none" {
        return Err(ClientError::NotFound(
            "a form or submit button for the filled fields (they were filled, not submitted)"
                .into(),
        ));
    }
    let deadline = tokio::time::Instant::now() + SUBMIT_WAIT;
    let mut navigated = false;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // While the new page loads, evaluating can fail: try again.
        match evaluate(cdp, page, MARKED).await {
            Ok(serde_json::Value::Bool(true)) => {}
            Ok(_) => {
                navigated = true;
                break;
            }
            Err(_) => {}
        }
    }
    let after = page_url(cdp, target_id).await?;
    Ok((navigated || after != before, after))
}

/// The permission a fill uses: `totp` for a one-time code
/// ([`FillOptions::totp`]), else `fill`.
fn fill_permission(options: &FillOptions<'_>) -> Permission {
    if options.totp {
        Permission::Totp
    } else {
        Permission::Fill
    }
}

/// With [`FillOptions::totp`], the field to type must be one TOTP field.
fn check_totp_field(item: &Item, names: &[String], options: &FillOptions<'_>) -> ClientResult<()> {
    if !options.totp {
        return Ok(());
    }
    match names {
        [name]
            if item
                .field(name)
                .is_some_and(|f| f.kind() == FieldKind::Totp) =>
        {
            Ok(())
        }
        _ => Err(ClientError::Invalid(
            "get_totp types only a one-time password field (…/totp)".into(),
        )),
    }
}

/// Fills `reference` (an item, or one field `…/field`) into the page.
/// Uses the `fill` permission (`totp` for a one-time code) with the page's
/// host as the domain claim. With `options.submit`, submits the form
/// afterwards.
#[allow(clippy::too_many_arguments)]
pub async fn fill(
    session: &mut Session,
    target: &BrowserTarget,
    reference: &str,
    scope: Option<(&str, &str)>,
    options: &FillOptions<'_>,
    reason: &str,
    wait: Duration,
) -> ClientResult<FillReport> {
    let selectors = options.selectors;
    let permission = fill_permission(options);
    let (item_id, field) = session.locate(reference, scope)?;
    session.check_claim(permission, &[item_id], None)?;
    let info = session.item_info(item_id)?;
    let mut cdp = Cdp::connect(&target.endpoint).await?;
    let result = async {
        let target_id = pick_target(&mut cdp, target.target_id.as_deref()).await?;
        let url = page_url(&mut cdp, &target_id).await?;
        let host = fillable_host(&url)?;
        if info.kind != ItemKind::Card && !url_matches(&url, &info.urls) {
            return Err(ClientError::Denied(format!(
                "the page is on {host}, which is not one of the item's addresses ({}): Klav does not fill it (phishing protection)",
                if info.urls.is_empty() {
                    "it has none".to_owned()
                } else {
                    info.urls.join(", ")
                }
            )));
        }
        let item = session
            .access_waiting(item_id, permission, reason, Some(&host), wait)
            .await?;
        check_delivered_urls(session, item_id, &item, &url, &host)?;
        let steps = plan(&item, field.as_deref(), selectors)?;
        let names: Vec<String> = steps.iter().map(|(n, _)| n.clone()).collect();
        check_totp_field(&item, &names, options)?;
        let attached = cdp
            .call(
                None,
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
            )
            .await?;
        let page = attached["sessionId"]
            .as_str()
            .ok_or_else(|| ClientError::Invalid("browser (CDP): no session".into()))?
            .to_owned();
        let mut filled = Vec::new();
        for (name, selector) in &steps {
            let kind = item
                .field(name)
                .map(|f| f.kind())
                .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?;
            let value = text_for(&item, name)?;
            // The page may have navigated meanwhile: checked right before
            // typing, with the focus.
            type_into(
                &mut cdp,
                &page,
                &target_id,
                &origin(&url),
                selector,
                InputRule::of(item.kind(), kind),
                value.expose(),
            )
            .await?;
            filled.push(name.clone());
        }
        let mut report = FillReport {
            url: origin(&url),
            filled,
            submitted: false,
            navigated: None,
            url_after: None,
            warnings: Vec::new(),
        };
        if options.submit
            && let Some((_, selector)) = steps.last()
        {
            // Never submit into another site than the one checked.
            let now = page_url(&mut cdp, &target_id).await?;
            if origin(&now) != origin(&url) {
                return Err(ClientError::Denied(format!(
                    "the page moved to {} before submitting: stopped",
                    origin(&now)
                )));
            }
            let (navigated, after) = submit(&mut cdp, &page, &target_id, selector).await?;
            report.submitted = true;
            report.navigated = Some(navigated);
            report.url_after = Some(origin(&after));
        }
        let _ = cdp
            .call(None, "Target.detachFromTarget", json!({ "sessionId": page }))
            .await;
        Ok(report)
    }
    .await;
    cdp.close().await;
    result
}

/// Directory of named browser sessions.
fn sessions_dir(home: &Home) -> PathBuf {
    home.file("browser-sessions")
}

fn session_path(home: &Home, name: &str) -> ClientResult<PathBuf> {
    crate::config::validate_name(name)?;
    Ok(sessions_dir(home).join(format!("{name}.json")))
}

/// Registers a browser as `sdk:<name>` for `klav mcp`.
pub fn register_session(home: &Home, name: &str, target: &BrowserTarget) -> ClientResult<()> {
    let url = Url::parse(&target.endpoint)
        .map_err(|e| ClientError::Invalid(format!("{}: {e}", target.endpoint)))?;
    if !is_loopback(&url) {
        return Err(ClientError::Invalid(
            "only a browser on this machine can be registered".into(),
        ));
    }
    let dir = sessions_dir(home);
    std::fs::create_dir_all(&dir)?;
    klav_client::home::set_mode(&dir, 0o700)?;
    let json = serde_json::to_vec_pretty(target)
        .map_err(|e| ClientError::Invalid(format!("session: {e}")))?;
    klav_client::home::write_private(&session_path(home, name)?, &json)
}

/// Removes a registered session.
pub fn forget_session(home: &Home, name: &str) -> ClientResult<()> {
    match std::fs::remove_file(session_path(home, name)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(ClientError::NotFound(format!("browser session {name:?}")))
        }
        Err(e) => Err(e.into()),
    }
}

/// A registered session.
pub fn load_session(home: &Home, name: &str) -> ClientResult<BrowserTarget> {
    let path = session_path(home, name)?;
    let bytes = std::fs::read(&path).map_err(|_| {
        ClientError::NotFound(format!(
            "browser session {name:?} (register it with the SDK or `klav agent browser register {name} …`)"
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ClientError::Corrupt(format!("browser session {name:?}: {e}")))
}

/// Where to fill.
#[derive(Debug, Clone)]
pub enum Target {
    /// A browser over CDP (a registered session, or `--cdp`).
    Cdp(BrowserTarget),
    /// The active tab of the person's browser, through `klavd` and Klav's
    /// extension. `klavd` is the one of `home` (or `$KLAV_BROWSER_HOME`).
    Extension {
        /// Where `klavd`'s socket is.
        home: Home,
    },
}

/// Parses a fill target: `sdk:<name>` (a registered session) or
/// `extension` (the person's browser, through Klav's extension).
pub fn resolve_target(home: &Home, target: &str) -> ClientResult<Target> {
    match target.split_once(':') {
        Some(("sdk", name)) => load_session(home, name).map(Target::Cdp),
        _ if target == "extension" => Ok(Target::Extension {
            home: browser_home(home),
        }),
        _ => Err(ClientError::Invalid(format!(
            "unknown target {target:?}: use \"extension\" or \"sdk:<name>\""
        ))),
    }
}

/// The `klavd` that has the person's browser attached: the agent's home,
/// unless `KLAV_BROWSER_HOME` names another one (an agent with its own
/// `KLAV_HOME` on the person's machine).
fn browser_home(home: &Home) -> Home {
    match std::env::var_os("KLAV_BROWSER_HOME") {
        Some(dir) if !dir.is_empty() => Home::at(PathBuf::from(dir)),
        _ => home.clone(),
    }
}

/// [`fill`] into any [`Target`].
#[allow(clippy::too_many_arguments)]
pub async fn fill_target(
    session: &mut Session,
    target: &Target,
    reference: &str,
    scope: Option<(&str, &str)>,
    options: &FillOptions<'_>,
    reason: &str,
    wait: Duration,
) -> ClientResult<FillReport> {
    match target {
        Target::Cdp(browser) => {
            fill(session, browser, reference, scope, options, reason, wait).await
        }
        Target::Extension { home } => {
            fill_extension(session, home, reference, scope, options, reason, wait).await
        }
    }
}

pub(crate) fn daemon_error(e: klav_daemon::protocol::ErrorBody) -> ClientError {
    use klav_daemon::protocol::ErrorCode;
    match e.code {
        ErrorCode::Denied => ClientError::Denied(e.message),
        // The person paused agents (ADR 0033 §7.2): exit 7, with the pause
        // (`scope`, `since`, `until`) when klavd says which.
        ErrorCode::AgentsPaused => ClientError::Paused(e.paused),
        // The person asked to delete the account, or it is already gone
        // (ADR 0037 §3): exit 8 either way. klavd says when in its message.
        ErrorCode::AccountDeleting | ErrorCode::AccountDeleted => {
            ClientError::AccountDeleting(None)
        }
        ErrorCode::NotFound => ClientError::NotFound(e.message),
        ErrorCode::Invalid | ErrorCode::BadRequest => ClientError::Invalid(e.message),
        ErrorCode::Security => ClientError::Security(e.message),
        ErrorCode::Locked => ClientError::Denied(format!(
            "klavd is locked: the person must unlock Klav on this computer ({})",
            e.message
        )),
        // With the presence gate on (ADR 0041 §3.1): klavd's message says
        // what to tell the person (bring the browser to the front, or wait
        // for the other prompt), so it reaches the agent as it is.
        ErrorCode::BrowserAmbiguous | ErrorCode::PresenceBusy => ClientError::Ambiguous(e.message),
        _ => ClientError::Network(format!("klavd: {}", e.message)),
    }
}

/// Fills through the extension (see the module docs).
#[allow(clippy::too_many_arguments)]
async fn fill_extension(
    session: &mut Session,
    home: &Home,
    reference: &str,
    scope: Option<(&str, &str)>,
    options: &FillOptions<'_>,
    reason: &str,
    wait: Duration,
) -> ClientResult<FillReport> {
    use klav_daemon::client::DaemonClient;
    use klav_daemon::protocol::{self, Request};

    let permission = fill_permission(options);
    let (item_id, field) = session.locate(reference, scope)?;
    session.check_claim(permission, &[item_id], None)?;
    let info = session.item_info(item_id)?;
    let mut daemon = DaemonClient::connect(home).await.ok_or_else(|| {
        ClientError::NotFound(
            "klavd, with the person's browser attached (open the browser with Klav's extension)"
                .into(),
        )
    })?;
    let (tab, _): (protocol::BrowserTab, _) = daemon
        .call(Request::BrowserTab)
        .await
        .map_err(daemon_error)?;
    let host = fillable_host(&tab.url)?;
    if info.kind != ItemKind::Card && !url_matches(&tab.url, &info.urls) {
        return Err(ClientError::Denied(format!(
            "the active tab is on {host}, which is not one of the item's addresses ({}): Klav does not fill it (phishing protection)",
            if info.urls.is_empty() {
                "it has none".to_owned()
            } else {
                info.urls.join(", ")
            }
        )));
    }
    let item = session
        .access_waiting(item_id, permission, reason, Some(&host), wait)
        .await?;
    check_delivered_urls(session, item_id, &item, &tab.url, &host)?;
    let names = plan_names(&item, field.as_deref())?;
    check_totp_field(&item, &names, options)?;
    let mut fields = Vec::new();
    for name in names {
        let kind = item
            .field(&name)
            .map(|f| f.kind())
            .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?;
        let value = text_for(&item, &name)?;
        fields.push(klav_client::fill::FillValue {
            name,
            kind,
            value: klav_client::ops::SecretText::from(&value),
        });
    }
    drop(item);
    let selectors: Vec<protocol::FieldSelector> = options
        .selectors
        .iter()
        .map(|s| protocol::FieldSelector {
            field: s.field.clone(),
            selector: s.selector.clone(),
        })
        .collect();
    // `item` lets klavd's presence prompt name the item's title from the
    // vault (ADR 0041 §3.1); `agent_id` lets it refuse a paused agent.
    let request = |agent_id, item| Request::BrowserFill {
        tab: tab.tab.clone(),
        host: host.clone(),
        agent: session.agent().name().to_owned(),
        agent_id,
        reason: reason.to_owned(),
        item,
        kind: info.kind,
        fields: fields.clone(),
        selectors: selectors.clone(),
        submit: options.submit,
    };
    let agent_id = Some(session.agent().id());
    let first = daemon
        .call::<FillReport>(request(agent_id, Some(item_id)))
        .await;
    let report = match first {
        // A `klavd` older than the presence gate does not know `item` and
        // cannot read the request; it has no presence prompt to name the
        // item in, so without it nothing is lost.
        Err(e) if is_unreadable(&e) => {
            match daemon.call::<FillReport>(request(agent_id, None)).await {
                // Older than the pause too: it does not know `agent_id`
                // either, nor pauses. Once more without, and the person
                // hears that it needs a restart.
                Err(e) if is_unreadable(&e) => {
                    let (mut report, _) = daemon
                        .call::<FillReport>(request(None, None))
                        .await
                        .map_err(daemon_error)?;
                    report.warnings.push(OLD_KLAVD.to_owned());
                    report
                }
                other => other.map_err(daemon_error)?.0,
            }
        }
        other => other.map_err(daemon_error)?.0,
    };
    Ok(report.trimmed())
}

/// What an agent tells the person when `klavd` is older than this SDK.
const OLD_KLAVD: &str = "klavd is older than this klav and cannot refuse a fill while the person pauses this agent: tell the person to restart it (`klav lock --stop`, then `klav unlock`)";

/// `klavd` could not read the request at all (`malformed request`).
fn is_unreadable(e: &klav_daemon::protocol::ErrorBody) -> bool {
    e.code == klav_daemon::protocol::ErrorCode::BadRequest && e.message == "malformed request"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_uses_the_core_site_rule() {
        let urls = vec!["https://github.com/login".to_owned()];
        assert!(host_matches("gist.github.com", &urls));
        assert!(!host_matches("github.com.evil.io", &urls));
        assert!(matches!(
            fillable_host("http://github.com/"),
            Err(ClientError::Denied(_))
        ));
    }

    #[test]
    fn targets() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        assert!(matches!(
            resolve_target(&home, "extension"),
            Ok(Target::Extension { .. })
        ));
        assert!(resolve_target(&home, "chrome").is_err());
        assert!(resolve_target(&home, "sdk:missing").is_err());
        let target = BrowserTarget {
            endpoint: "http://127.0.0.1:9222".into(),
            target_id: Some("T1".into()),
        };
        register_session(&home, "shop", &target).unwrap();
        assert!(matches!(
            resolve_target(&home, "sdk:shop").unwrap(),
            Target::Cdp(BrowserTarget { target_id: Some(t), .. }) if t == "T1"
        ));
        assert!(
            register_session(
                &home,
                "far",
                &BrowserTarget {
                    endpoint: "http://10.0.0.1:9222".into(),
                    target_id: None
                }
            )
            .is_err()
        );
        forget_session(&home, "shop").unwrap();
        assert!(resolve_target(&home, "sdk:shop").is_err());
    }
}
