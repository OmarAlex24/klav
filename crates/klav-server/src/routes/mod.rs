//! HTTP handlers, grouped by resource.

use axum::Router;

use crate::state::AppState;

mod account;
pub(crate) mod agent_access;
pub(crate) mod agents;
mod approvals;
mod attachments;
mod audit;
mod auth;
mod auto_invites;
mod devices;
mod health;
mod items;
mod rotate;
mod rotation;
mod sandboxes;
pub(crate) mod secret_requests;
mod sync;
pub(crate) mod tasks;
mod vaults;

pub(crate) fn router(max_attachment_chunk: usize) -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(account::router())
        .merge(agents::router())
        .merge(agent_access::router())
        .merge(approvals::router())
        .merge(audit::router())
        .merge(auth::router())
        .merge(auto_invites::router())
        .merge(devices::router())
        .merge(vaults::router())
        .merge(items::router())
        .merge(rotation::router())
        .merge(rotate::router())
        .merge(sandboxes::router())
        .merge(secret_requests::router())
        .merge(attachments::router(max_attachment_chunk))
        .merge(sync::router())
        .merge(tasks::router())
}
