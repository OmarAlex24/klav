//! Server URL validation.

use crate::error::{ClientError, ClientResult};

/// A validated server base URL (no trailing slash).
///
/// Session tokens travel in `Authorization` headers, so plain `http://` is
/// only accepted for loopback hosts (local development and tests). Everything
/// else must use `https://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl(reqwest::Url);

impl ServerUrl {
    /// Parses and validates `text`.
    pub fn parse(text: &str) -> ClientResult<Self> {
        let url =
            reqwest::Url::parse(text.trim()).map_err(|e| ClientError::ServerUrl(e.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ClientError::ServerUrl(
                "credentials are not allowed in the URL".into(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ClientError::ServerUrl(
                "query strings and fragments are not allowed".into(),
            ));
        }
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(&url) => {}
            "http" => {
                return Err(ClientError::ServerUrl(
                    "plain http:// is only allowed for localhost; use https://".into(),
                ));
            }
            other => {
                return Err(ClientError::ServerUrl(format!(
                    "unsupported scheme {other}"
                )));
            }
        }
        Ok(Self(url))
    }

    /// The URL of an API path (`path` starts with `/v1/`).
    pub fn join(&self, path: &str) -> String {
        format!("{}{path}", self.as_str())
    }

    /// The host (a name or an address).
    pub fn host(&self) -> &str {
        self.0.host_str().unwrap_or_default()
    }

    /// Canonical text form, without a trailing slash.
    pub fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_everywhere_http_only_on_loopback() {
        assert!(ServerUrl::parse("https://klav.example.com").is_ok());
        assert!(ServerUrl::parse("http://127.0.0.1:8080").is_ok());
        assert!(ServerUrl::parse("http://localhost:8080/").is_ok());
        assert!(ServerUrl::parse("http://[::1]:8080").is_ok());
        assert!(ServerUrl::parse("http://klav.example.com").is_err());
        assert!(ServerUrl::parse("ftp://x").is_err());
        assert!(ServerUrl::parse("https://u:p@x").is_err());
        assert!(ServerUrl::parse("https://x/?a=1").is_err());
        assert_eq!(
            ServerUrl::parse("https://x.example/base/")
                .unwrap()
                .join("/v1/health"),
            "https://x.example/base/v1/health"
        );
    }
}
