//! Shared state of one invocation.

use klav_client::Home;

use crate::backend::{self, Backend};
use crate::error::CliResult;
use crate::input::Input;

pub(crate) struct Ctx {
    pub(crate) home: Home,
    pub(crate) input: Input,
    /// `--no-daemon`.
    pub(crate) no_daemon: bool,
    backend: Option<Backend>,
}

impl Ctx {
    pub(crate) fn new(home: Home, input: Input, no_daemon: bool) -> Self {
        Self {
            home,
            input,
            no_daemon,
            backend: None,
        }
    }

    /// Forgets the unlocked state (keys and decrypted items) now.
    pub(crate) fn close(&mut self) {
        self.backend = None;
    }

    /// The unlocked backend, opened on first use.
    pub(crate) async fn backend(&mut self) -> CliResult<&mut Backend> {
        if self.backend.is_none() {
            let from_daemon = if self.no_daemon {
                None
            } else {
                backend::daemon(&self.home, &mut self.input).await?
            };
            let opened = match from_daemon {
                Some(b) => b,
                None => backend::direct(&self.home, &mut self.input).await?,
            };
            self.backend = Some(opened);
        }
        Ok(self.backend.as_mut().expect("just set"))
    }
}

/// The host name, as the default device name.
pub(crate) fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.trim_end_matches(".local").to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "klav-cli".to_owned())
}
