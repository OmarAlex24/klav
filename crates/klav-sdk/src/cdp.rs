//! A minimal Chrome DevTools Protocol client: just what `fill` needs
//! (ADR 0014 §9). Only loopback endpoints are accepted: values travel over
//! a plain WebSocket.

use futures_util::{SinkExt, StreamExt};
use klav_client::{ClientError, ClientResult};
use reqwest::Url;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

/// How long one CDP call may take.
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn cdp_error(message: impl std::fmt::Display) -> ClientError {
    ClientError::Invalid(format!("browser (CDP): {message}"))
}

/// Whether `url` points to this machine.
pub use klav_core::site::is_loopback;

/// A connection to a browser.
pub struct Cdp {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl Cdp {
    /// Connects to `endpoint`: the browser's WebSocket URL
    /// (`ws://127.0.0.1:9222/devtools/browser/…`) or its HTTP address
    /// (`http://127.0.0.1:9222`), from which the WebSocket URL is read.
    pub async fn connect(endpoint: &str) -> ClientResult<Self> {
        let url = Url::parse(endpoint.trim()).map_err(|e| cdp_error(format!("{endpoint}: {e}")))?;
        if !is_loopback(&url) {
            return Err(cdp_error(
                "only a browser on this machine (127.0.0.1, ::1 or localhost) can be used",
            ));
        }
        let ws_url = match url.scheme() {
            "ws" => url,
            "http" => {
                let version: Value = reqwest::Client::new()
                    .get(url.join("/json/version").map_err(cdp_error)?)
                    .timeout(CALL_TIMEOUT)
                    .send()
                    .await
                    .map_err(cdp_error)?
                    .json()
                    .await
                    .map_err(cdp_error)?;
                let ws = version
                    .get("webSocketDebuggerUrl")
                    .and_then(Value::as_str)
                    .ok_or_else(|| cdp_error("no webSocketDebuggerUrl in /json/version"))?;
                let ws = Url::parse(ws).map_err(cdp_error)?;
                if !is_loopback(&ws) {
                    return Err(cdp_error("the browser announced a non-local WebSocket"));
                }
                ws
            }
            other => return Err(cdp_error(format!("unsupported scheme {other:?}"))),
        };
        let (ws, _) = tokio::time::timeout(
            CALL_TIMEOUT,
            tokio_tungstenite::connect_async(ws_url.as_str()),
        )
        .await
        .map_err(|_| cdp_error("timed out connecting"))?
        .map_err(cdp_error)?;
        Ok(Self { ws, next_id: 1 })
    }

    /// Calls `method` (in the page `session`, if given) and returns its
    /// result.
    pub async fn call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> ClientResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            message["sessionId"] = Value::String(s.to_owned());
        }
        self.send_and_wait(id, Zeroizing::new(message.to_string()))
            .await
    }

    /// Types `text` into the focused element (`Input.insertText`). The
    /// message is built in a zeroizing buffer.
    pub async fn insert_text(&mut self, session: &str, text: &str) -> ClientResult<()> {
        #[derive(serde::Serialize)]
        struct Params<'a> {
            text: &'a str,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Call<'a> {
            id: u64,
            method: &'a str,
            params: Params<'a>,
            session_id: &'a str,
        }
        let id = self.next_id;
        self.next_id += 1;
        let message = Zeroizing::new(
            serde_json::to_string(&Call {
                id,
                method: "Input.insertText",
                params: Params { text },
                session_id: session,
            })
            .map_err(cdp_error)?,
        );
        self.send_and_wait(id, message).await.map(drop)
    }

    async fn send_and_wait(&mut self, id: u64, message: Zeroizing<String>) -> ClientResult<Value> {
        self.ws
            .send(Message::text(message.as_str()))
            .await
            .map_err(cdp_error)?;
        drop(message);
        let wait = async {
            while let Some(msg) = self.ws.next().await {
                let msg = msg.map_err(cdp_error)?;
                let Message::Text(text) = msg else { continue };
                let value: Value = serde_json::from_str(text.as_str()).map_err(cdp_error)?;
                if value.get("id").and_then(Value::as_u64) != Some(id) {
                    continue; // an event or another reply
                }
                if let Some(error) = value.get("error") {
                    return Err(cdp_error(
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("error"),
                    ));
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
            Err(cdp_error("the browser closed the connection"))
        };
        tokio::time::timeout(CALL_TIMEOUT, wait)
            .await
            .map_err(|_| cdp_error("timed out"))?
    }

    /// Closes the connection.
    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
