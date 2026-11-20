//! Shared application state.

use std::sync::Arc;

use klav_core::ids::{AccountId, ApprovalId, TaskId, VaultId};
use tokio::sync::broadcast;

use crate::config::Config;
use crate::db::Db;
use crate::deletion::DeletionLimits;
use crate::keys::ServerKeys;
use crate::logins::PendingLogins;
use crate::push::{Phone, PushKind, Pusher};
use crate::ratelimit::RateLimiter;
use crate::storage::AttachmentStore;

/// Cheaply clonable handle to everything handlers need.
#[derive(Clone)]
pub(crate) struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    db: Db,
    limiter: RateLimiter,
    keys: ServerKeys,
    logins: PendingLogins,
    changes: broadcast::Sender<VaultChange>,
    /// Approvals the person just decided (wakes agents' long-polls).
    approvals: broadcast::Sender<ApprovalId>,
    /// Tasks the person just decided or someone ended (wakes long-polls).
    tasks: broadcast::Sender<TaskId>,
    /// Accounts just deleted (closes their event streams, ADR 0037 §5.2).
    deleted_accounts: broadcast::Sender<AccountId>,
    deletion_limits: DeletionLimits,
    attachments: AttachmentStore,
    pusher: Pusher,
}

/// A committed change: `vault` reached `revision`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VaultChange {
    pub(crate) vault: VaultId,
    pub(crate) revision: u64,
}

impl AppState {
    pub(crate) fn new(config: Config, db: Db, keys: ServerKeys, pusher: Pusher) -> Self {
        let attachments = AttachmentStore::new(&config.data_dir);
        Self(Arc::new(Inner {
            attachments,
            config,
            db,
            limiter: RateLimiter::default(),
            keys,
            logins: PendingLogins::default(),
            changes: broadcast::channel(1024).0,
            approvals: broadcast::channel(256).0,
            tasks: broadcast::channel(256).0,
            deleted_accounts: broadcast::channel(64).0,
            deletion_limits: DeletionLimits::default(),
            pusher,
        }))
    }

    pub(crate) fn keys(&self) -> &ServerKeys {
        &self.0.keys
    }

    pub(crate) fn logins(&self) -> &PendingLogins {
        &self.0.logins
    }

    /// Announces a committed change (fan-out to change subscribers).
    pub(crate) fn notify(&self, vault: VaultId, revision: u64) {
        // No subscribers is not an error.
        let _ = self.0.changes.send(VaultChange { vault, revision });
    }

    /// Announces a decision on an approval to the agents waiting on it.
    pub(crate) fn approval_decided(&self, id: ApprovalId) {
        let _ = self.0.approvals.send(id);
    }

    /// Subscribes to decisions on approvals (this instance only: waiters
    /// also re-read the database).
    pub(crate) fn subscribe_approvals(&self) -> broadcast::Receiver<ApprovalId> {
        self.0.approvals.subscribe()
    }

    /// Announces that a task changed (decided, revised or ended).
    pub(crate) fn task_changed(&self, id: TaskId) {
        let _ = self.0.tasks.send(id);
    }

    /// Subscribes to task changes (this instance only: waiters also re-read
    /// the database).
    pub(crate) fn subscribe_tasks(&self) -> broadcast::Receiver<TaskId> {
        self.0.tasks.subscribe()
    }

    /// Tells the account's phones (APNs), in the background. No-op when
    /// pushes are not configured.
    pub(crate) fn push(&self, account: AccountId, kind: PushKind, id: String) {
        self.0.pusher.notify(&self.0.db, account, kind, id);
    }

    /// Tells `phones`, read before they were deleted, in the background.
    pub(crate) fn push_to(&self, account: AccountId, kind: PushKind, phones: Vec<Phone>) {
        self.0
            .pusher
            .notify_phones(&self.0.db, account, kind, phones);
    }

    /// Limits of asking for a deletion of the account.
    pub(crate) fn deletion_limits(&self) -> &DeletionLimits {
        &self.0.deletion_limits
    }

    /// Announces that `account` was deleted (its event streams close).
    pub(crate) fn account_deleted(&self, account: AccountId) {
        let _ = self.0.deleted_accounts.send(account);
    }

    /// Subscribes to deleted accounts (this instance only: streams also
    /// re-check their session every 30 s).
    pub(crate) fn subscribe_deleted_accounts(&self) -> broadcast::Receiver<AccountId> {
        self.0.deleted_accounts.subscribe()
    }

    pub(crate) fn attachments(&self) -> &AttachmentStore {
        &self.0.attachments
    }

    /// Subscribes to committed changes of every vault.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<VaultChange> {
        self.0.changes.subscribe()
    }

    pub(crate) fn config(&self) -> &Config {
        &self.0.config
    }

    pub(crate) fn db(&self) -> &Db {
        &self.0.db
    }

    pub(crate) fn limiter(&self) -> &RateLimiter {
        &self.0.limiter
    }
}
