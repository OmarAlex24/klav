//! Agents filling through the browser extension (ADR 0017).
//!
//! The extension attaches its connection (`extension_attach`) and then
//! receives [`Event`] lines on it. An agent asks for the active tab
//! (`browser_tab`), checks its address against the item and fetches the
//! values under its own grant, and sends them with `browser_fill`; the
//! extension types them only if the tab is still on that host, tells the
//! person, and answers with field names and addresses, never values.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use klav_client::fill::FillValue;
use klav_core::model::item::ItemKind;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use klav_client::ops::SecretText;

use crate::protocol::{
    BrowserSeen, BrowserTab, ErrorBody, ErrorCode, Event, EventEnvelope, ExtensionTab,
    FieldSelector, PROTOCOL_VERSION, RotateTarget,
};

/// A line to write on a connection.
pub(crate) type Line = Zeroizing<Vec<u8>>;

/// How long a browser has to say which tab is active.
const TAB_WAIT: Duration = Duration::from_secs(5);
/// How long a fill may take (a submit waits up to 10 s for the next page).
const FILL_WAIT: Duration = Duration::from_secs(40);
/// How long the frames of a tab have to say where a change would fill.
const PROBE_WAIT: Duration = Duration::from_secs(5);
/// How long an event may wait to be queued for an extension. One that
/// stops reading is detached, instead of holding the agent's request.
const SEND_WAIT: Duration = Duration::from_secs(5);
/// Longest agent name shown in the page's notice.
const MAX_AGENT_SHOWN: usize = 64;
/// Longest host accepted (DNS: 253).
const MAX_HOST: usize = 253;

struct Extension {
    conn: u64,
    browser: String,
    events: mpsc::Sender<Line>,
}

struct Waiting {
    conn: u64,
    reply: oneshot::Sender<Result<serde_json::Value, ErrorBody>>,
}

#[derive(Default)]
struct Inner {
    /// Newest last.
    extensions: Vec<Extension>,
    waiting: HashMap<u64, Waiting>,
    /// Every browser that attached since `klavd` started, by name: when it
    /// last attached or left. At most [`MAX_SEEN`].
    seen: Vec<(String, u64)>,
}

/// How many browser names `status` remembers.
const MAX_SEEN: usize = 16;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Inner {
    fn mark(&mut self, browser: &str) {
        let now = now_ms();
        match self.seen.iter_mut().find(|(name, _)| name == browser) {
            Some(entry) => entry.1 = now,
            None => {
                if self.seen.len() == MAX_SEEN {
                    self.seen.remove(0);
                }
                self.seen.push((browser.to_owned(), now));
            }
        }
    }
}

/// The attached extensions and the events they have not answered yet.
#[derive(Default)]
pub(crate) struct Hub {
    next_conn: AtomicU64,
    next_event: AtomicU64,
    inner: Mutex<Inner>,
}

fn error(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        code,
        message: message.into(),
        paused: None,
        presence: None,
    }
}

fn no_browser() -> ErrorBody {
    error(
        ErrorCode::NotFound,
        "no browser with Klav's extension is connected: open the browser (with the extension installed and `klav extension install-host` run once)",
    )
}

impl Hub {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new connection's ID.
    pub(crate) fn connection(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Registers connection `conn` as an extension (again: replaces).
    pub(crate) fn attach(&self, conn: u64, browser: String, events: mpsc::Sender<Line>) {
        let mut inner = self.inner();
        inner.extensions.retain(|e| e.conn != conn);
        inner.mark(&browser);
        inner.extensions.push(Extension {
            conn,
            browser,
            events,
        });
    }

    /// The browsers that attached since `klavd` started, newest first.
    pub(crate) fn seen(&self) -> Vec<BrowserSeen> {
        let inner = self.inner();
        let mut list: Vec<BrowserSeen> = inner
            .seen
            .iter()
            .map(|(browser, at_ms)| BrowserSeen {
                browser: browser.clone(),
                connected: inner.extensions.iter().any(|e| &e.browser == browser),
                at_ms: *at_ms,
            })
            .collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.at_ms));
        list
    }

    /// Connection `conn` closed: forget it and fail what it owed.
    pub(crate) fn detach(&self, conn: u64) {
        let mut inner = self.inner();
        let left = inner
            .extensions
            .iter()
            .find(|e| e.conn == conn)
            .map(|e| e.browser.clone());
        inner.extensions.retain(|e| e.conn != conn);
        if let Some(browser) = left
            && !inner.extensions.iter().any(|e| e.browser == browser)
        {
            inner.mark(&browser);
        }
        let gone: Vec<u64> = inner
            .waiting
            .iter()
            .filter(|(_, w)| w.conn == conn)
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            if let Some(w) = inner.waiting.remove(&id) {
                let _ = w
                    .reply
                    .send(Err(error(ErrorCode::Internal, "the browser closed")));
            }
        }
    }

    /// An extension answered event `event` (only the connection it was sent to may).
    pub(crate) fn reply(
        &self,
        conn: u64,
        event: u64,
        result: Result<serde_json::Value, ErrorBody>,
    ) -> Result<(), ErrorBody> {
        let mut inner = self.inner();
        match inner.waiting.get(&event) {
            Some(w) if w.conn == conn => {}
            _ => return Err(error(ErrorCode::NotFound, "no such event")),
        }
        if let Some(w) = inner.waiting.remove(&event) {
            let _ = w.reply.send(result);
        }
        Ok(())
    }

    async fn ask(
        &self,
        conn: u64,
        events: &mpsc::Sender<Line>,
        event: impl FnOnce(u64) -> Event,
        wait: Duration,
    ) -> Result<serde_json::Value, ErrorBody> {
        let id = self.next_event.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.inner().waiting.insert(id, Waiting { conn, reply: tx });
        let envelope = EventEnvelope {
            v: PROTOCOL_VERSION,
            event: event(id),
        };
        let mut line = Zeroizing::new(
            serde_json::to_vec(&envelope).map_err(|e| error(ErrorCode::Internal, e.to_string()))?,
        );
        drop(envelope);
        line.push(b'\n');
        match tokio::time::timeout(SEND_WAIT, events.send(line)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                self.inner().waiting.remove(&id);
                return Err(error(ErrorCode::Internal, "the browser closed"));
            }
            Err(_) => {
                // The extension stopped reading: forget it.
                self.detach(conn);
                return Err(error(
                    ErrorCode::Internal,
                    "the browser is not answering; it was disconnected",
                ));
            }
        }
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(error(ErrorCode::Internal, "the browser closed")),
            Err(_) => {
                self.inner().waiting.remove(&id);
                Err(error(
                    ErrorCode::Internal,
                    "the browser did not answer in time",
                ))
            }
        }
    }

    /// The active tab of the focused browser (else of the newest one).
    pub(crate) async fn tab(&self) -> Result<BrowserTab, ErrorBody> {
        let extensions: Vec<(u64, String, mpsc::Sender<Line>)> = self
            .inner()
            .extensions
            .iter()
            .rev()
            .map(|e| (e.conn, e.browser.clone(), e.events.clone()))
            .collect();
        if extensions.is_empty() {
            return Err(no_browser());
        }
        let mut found: Vec<(u64, String, ExtensionTab)> = Vec::new();
        let mut last_error = None;
        for (conn, browser, events) in extensions {
            match self
                .ask(conn, &events, |id| Event::Tab { id }, TAB_WAIT)
                .await
                .and_then(|v| {
                    serde_json::from_value::<ExtensionTab>(v)
                        .map_err(|e| error(ErrorCode::Internal, format!("browser: {e}")))
                }) {
                Ok(tab) => found.push((conn, browser, tab)),
                Err(e) => last_error = Some(e),
            }
        }
        let pick = found.iter().position(|(_, _, t)| t.focused).unwrap_or(0);
        if found.is_empty() {
            return Err(last_error.unwrap_or_else(no_browser));
        }
        let (conn, browser, tab) = found.swap_remove(pick);
        // Only the origin goes to the agent: a page's path, query and
        // fragment may carry tokens (the agent only needs the host).
        Ok(BrowserTab {
            tab: format!("{conn}.{}", tab.tab_id),
            url: klav_core::site::origin(&tab.url),
            browser,
        })
    }

    /// The browser connection and tab ID behind `tab`, for state bound to
    /// that tab (an agent's passkey use, ADR 0020 §9).
    pub(crate) fn tab_ids(&self, tab: &str) -> Result<(u64, u64), ErrorBody> {
        self.route(tab).map(|(conn, tab_id, _)| (conn, tab_id))
    }

    /// Tells tab `tab` an agent's passkey use is armed there (ADR 0020
    /// §9). The extension checks the tab is still on `host`; the answer is
    /// `{used}` (the page already waited and got it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn passkey_arm(
        &self,
        tab: &str,
        host: String,
        rp_id: String,
        item: String,
        title: String,
        agent: String,
        reason: String,
        token: SecretText,
        expires_in_ms: u64,
    ) -> Result<serde_json::Value, ErrorBody> {
        let (agent, reason) = shown_notice(&agent, &reason);
        let title = klav_core::text::shown(&title, MAX_AGENT_SHOWN);
        let host = checked_host(&host)?;
        let (conn, tab_id, events) = self.route(tab)?;
        self.ask(
            conn,
            &events,
            move |id| Event::PasskeyArm {
                id,
                tab_id,
                host,
                rp_id,
                item,
                title,
                agent,
                reason,
                token,
                expires_in_ms,
            },
            FILL_WAIT,
        )
        .await
    }

    /// The browser connection and tab ID behind `tab` ([`BrowserTab::tab`]).
    fn route(&self, tab: &str) -> Result<(u64, u64, mpsc::Sender<Line>), ErrorBody> {
        let (conn, tab_id) = tab
            .split_once('.')
            .and_then(|(c, t)| Some((c.parse::<u64>().ok()?, t.parse::<u64>().ok()?)))
            .ok_or_else(|| error(ErrorCode::BadRequest, "unknown tab: ask browser_tab first"))?;
        let events = self
            .inner()
            .extensions
            .iter()
            .find(|e| e.conn == conn)
            .map(|e| e.events.clone())
            .ok_or_else(|| {
                error(
                    ErrorCode::NotFound,
                    "that browser closed: ask browser_tab again",
                )
            })?;
        Ok((conn, tab_id, events))
    }

    /// Asks tab `tab` where an assisted change would fill (ADR 0022 §5).
    pub(crate) async fn rotate_probe(
        &self,
        tab: &str,
        host: String,
        urls: Vec<String>,
    ) -> Result<RotateTarget, ErrorBody> {
        let host = checked_host(&host)?;
        let (conn, tab_id, events) = self.route(tab)?;
        let value = self
            .ask(
                conn,
                &events,
                move |id| Event::RotateProbe {
                    id,
                    tab_id,
                    host,
                    urls,
                },
                PROBE_WAIT,
            )
            .await?;
        serde_json::from_value(value)
            .map_err(|e| error(ErrorCode::Internal, format!("browser: {e}")))
    }

    /// Fills the change form `target` found in tab `tab`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn rotate_fill(
        &self,
        tab: &str,
        target: &RotateTarget,
        host: String,
        agent: String,
        reason: String,
        current: SecretText,
        new: SecretText,
        submit: bool,
    ) -> Result<serde_json::Value, ErrorBody> {
        let (agent, reason) = shown_notice(&agent, &reason);
        let host = checked_host(&host)?;
        let (conn, tab_id, events) = self.route(tab)?;
        let (frame_id, document_id, token) = (
            target.frame_id,
            target.document_id.clone(),
            target.token.clone(),
        );
        let report = self
            .ask(
                conn,
                &events,
                move |id| Event::RotateFill {
                    id,
                    tab_id,
                    frame_id,
                    document_id,
                    token,
                    host,
                    agent,
                    reason,
                    current,
                    new,
                    submit,
                },
                FILL_WAIT,
            )
            .await?;
        Ok(origins_only(report))
    }

    /// Fills tab `tab` ([`BrowserTab::tab`]).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn fill(
        &self,
        tab: &str,
        host: String,
        agent: String,
        reason: String,
        kind: ItemKind,
        fields: Vec<FillValue>,
        selectors: Vec<FieldSelector>,
        submit: bool,
    ) -> Result<serde_json::Value, ErrorBody> {
        let (agent, reason) = shown_notice(&agent, &reason);
        let host = checked_host(&host)?;
        let (conn, tab_id, events) = self.route(tab)?;
        let report = self
            .ask(
                conn,
                &events,
                move |id| Event::Fill {
                    id,
                    tab_id,
                    host,
                    agent,
                    reason,
                    item_kind: kind,
                    fields,
                    selectors,
                    submit,
                },
                FILL_WAIT,
            )
            .await?;
        Ok(origins_only(report))
    }
}

/// What the agent declares is shown on the page (the notice): the same
/// filter as the extension's own name, and the extension says the name is
/// the agent's word.
fn shown_notice(agent: &str, reason: &str) -> (String, String) {
    (
        klav_core::text::shown(agent, MAX_AGENT_SHOWN),
        klav_core::text::shown(reason, klav_proto::agent::MAX_REASON),
    )
}

/// The host a fill is for, normalized; anything that is not a host name
/// or address is refused.
fn checked_host(host: &str) -> Result<String, ErrorBody> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.len() > MAX_HOST
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err(error(ErrorCode::BadRequest, "invalid host"));
    }
    Ok(host)
}

/// What a fill reports back to the agent: whatever the extension says, the
/// agent gets origins only, never a full URL (ADR 0030 §4).
fn origins_only(mut report: serde_json::Value) -> serde_json::Value {
    for key in ["url", "url_after"] {
        if let Some(url) = report.get(key).and_then(serde_json::Value::as_str) {
            report[key] = serde_json::Value::String(klav_core::site::origin(url));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_remembers_the_browsers_that_attached() {
        let hub = Hub::default();
        let (tx, _rx) = mpsc::channel(1);
        assert!(hub.seen().is_empty());
        hub.attach(1, "Dia".into(), tx.clone());
        hub.attach(2, "Google Chrome".into(), tx.clone());
        hub.attach(3, "Dia".into(), tx.clone());
        let seen = hub.seen();
        assert_eq!(seen.len(), 2, "one entry per browser");
        assert!(seen.iter().all(|b| b.connected));

        // One of Dia's two connections leaves: still connected.
        hub.detach(1);
        assert!(hub.seen().iter().any(|b| b.browser == "Dia" && b.connected));
        hub.detach(3);
        let dia = hub.seen().into_iter().find(|b| b.browser == "Dia").unwrap();
        assert!(!dia.connected, "gone, but remembered");
        assert!(dia.at_ms > 0);

        for n in 0..40 {
            hub.attach(100 + n, format!("browser {n}"), tx.clone());
        }
        assert_eq!(hub.seen().len(), MAX_SEEN);
    }
}
