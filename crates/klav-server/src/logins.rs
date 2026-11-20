//! OPAQUE exchanges in progress: logins (between `login/start` and
//! `login/finish`) and the reauthentications that delete an account
//! (between `account/delete/start` and `…/finish`, ADR 0037 §1).
//!
//! The server state of an exchange contains ephemeral key-exchange secrets,
//! so it stays in memory (never in the database) and expires after
//! [`LOGIN_TTL`]. With several server instances, `start` and `finish` must
//! reach the same instance (sticky routing).
//!
//! Each exchange is bound to its [`Purpose`]: a login's handle cannot finish
//! a deletion, and a deletion's handle can only finish the deletion of the
//! session that started it (threat T166). A handle is taken out of the
//! table on its first use, whatever the outcome.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use klav_core::crypto::opaque::ServerLogin;
use klav_core::crypto::token::generate_token;
use klav_core::ids::AccountId;
use secrecy::ExposeSecret;

/// How long a client has to finish a login.
pub(crate) const LOGIN_TTL: Duration = Duration::from_secs(120);
/// Hard cap on pending exchanges (memory bound under a flood of `start`s).
const MAX_PENDING: usize = 10_000;

/// What an OPAQUE exchange is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// `POST /v1/auth/login/…`: opens a session.
    Login,
    /// `POST /v1/account/delete/…`: schedules the deletion of the account,
    /// from this session only.
    DeleteAccount {
        /// The session that started it.
        session_id: String,
    },
}

impl Purpose {
    /// Handles of different purposes look different, which helps nobody
    /// mix them up (the binding itself is checked on `take`).
    fn prefix(&self) -> &'static str {
        match self {
            Self::Login => "lgn_",
            Self::DeleteAccount { .. } => "del_",
        }
    }
}

pub(crate) struct Pending {
    pub(crate) login: ServerLogin,
    /// `None` for an unknown e-mail (the decoy login can never finish).
    pub(crate) account_id: Option<AccountId>,
    pub(crate) purpose: Purpose,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct PendingLogins {
    map: Mutex<HashMap<String, Pending>>,
}

impl PendingLogins {
    /// Stores a pending exchange and returns its handle, or `None` when the
    /// table is full.
    pub(crate) fn insert(
        &self,
        login: ServerLogin,
        account_id: Option<AccountId>,
        purpose: Purpose,
    ) -> Option<String> {
        self.insert_at(login, account_id, purpose, Instant::now())
    }

    fn insert_at(
        &self,
        login: ServerLogin,
        account_id: Option<AccountId>,
        purpose: Purpose,
        now: Instant,
    ) -> Option<String> {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_PENDING {
            map.retain(|_, p| p.expires > now);
            if map.len() >= MAX_PENDING {
                return None;
            }
        }
        let id = generate_token(purpose.prefix()).expose_secret().to_owned();
        map.insert(
            id.clone(),
            Pending {
                login,
                account_id,
                purpose,
                expires: now + LOGIN_TTL,
            },
        );
        Some(id)
    }

    /// Removes the exchange `id` and returns it if it has not expired and
    /// is for `purpose`. A handle can be used once only: one taken for the
    /// wrong purpose is gone too.
    pub(crate) fn take(&self, id: &str, purpose: &Purpose) -> Option<Pending> {
        self.take_at(id, purpose, Instant::now())
    }

    fn take_at(&self, id: &str, purpose: &Purpose, now: Instant) -> Option<Pending> {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(id)
            .filter(|p| p.expires > now && &p.purpose == purpose)
    }

    /// Forgets every exchange of `account` (its deletion, ADR 0037 §5.2).
    pub(crate) fn forget_account(&self, account: AccountId) {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.retain(|_, p| p.account_id != Some(account));
    }
}

#[cfg(test)]
mod tests {
    use klav_core::crypto::kdf::{KdfParams, MasterPassword, derive_account_keys};
    use klav_core::crypto::opaque::{self, ServerSetup};
    use klav_core::crypto::random;
    use klav_core::crypto::secret_key::SecretKey;

    use super::*;

    /// A server-side login state (its contents do not matter here).
    fn server_login() -> ServerLogin {
        let setup = ServerSetup::generate();
        let params = KdfParams::insecure_for_tests(64, 1, 1, random::array());
        let keys = derive_account_keys(&MasterPassword::new("pw"), &SecretKey::generate(), &params)
            .expect("derive");
        let (_, ke1) = opaque::client_start_login(keys.opaque_input()).expect("ke1");
        opaque::server_start_login(&setup, None, &ke1, b"ana@example.com")
            .expect("decoy login")
            .0
    }

    fn delete(session: &str) -> Purpose {
        Purpose::DeleteAccount {
            session_id: session.into(),
        }
    }

    #[test]
    fn a_handle_finishes_only_what_it_was_started_for() {
        let logins = PendingLogins::default();
        let account = Some(AccountId::generate());
        // A login's handle cannot finish a deletion, and is spent.
        let id = logins
            .insert(server_login(), account, Purpose::Login)
            .unwrap();
        assert!(id.starts_with("lgn_"));
        assert!(logins.take(&id, &delete("s1")).is_none());
        assert!(logins.take(&id, &Purpose::Login).is_none());
        // A deletion's handle cannot finish a login, and is spent.
        let id = logins
            .insert(server_login(), account, delete("s1"))
            .unwrap();
        assert!(id.starts_with("del_"));
        assert!(logins.take(&id, &Purpose::Login).is_none());
        assert!(logins.take(&id, &delete("s1")).is_none());
        // Nor a deletion from another session.
        let id = logins
            .insert(server_login(), account, delete("s1"))
            .unwrap();
        assert!(logins.take(&id, &delete("s2")).is_none());
        assert!(logins.take(&id, &delete("s1")).is_none());
        // The right one works once.
        let id = logins
            .insert(server_login(), account, delete("s1"))
            .unwrap();
        assert!(logins.take(&id, &delete("s1")).is_some());
        assert!(logins.take(&id, &delete("s1")).is_none());
    }

    #[test]
    fn handles_expire() {
        let logins = PendingLogins::default();
        let start = Instant::now();
        let id = logins
            .insert_at(server_login(), None, delete("s1"), start)
            .unwrap();
        assert!(
            logins
                .take_at(&id, &delete("s1"), start + LOGIN_TTL)
                .is_none()
        );
    }

    #[test]
    fn a_deleted_account_leaves_no_exchange_behind() {
        let logins = PendingLogins::default();
        let ana = AccountId::generate();
        let bob = AccountId::generate();
        let a = logins
            .insert(server_login(), Some(ana), Purpose::Login)
            .unwrap();
        let b = logins
            .insert(server_login(), Some(ana), delete("s1"))
            .unwrap();
        let c = logins
            .insert(server_login(), Some(bob), Purpose::Login)
            .unwrap();
        logins.forget_account(ana);
        assert!(logins.take(&a, &Purpose::Login).is_none());
        assert!(logins.take(&b, &delete("s1")).is_none());
        assert!(logins.take(&c, &Purpose::Login).is_some());
    }
}
