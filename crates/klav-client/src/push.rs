//! This device's push token (approvals on the phone, ADR 0018 §5).

use klav_proto::auth::{PushEnvironment, PushRegistration};
use reqwest::Method;

use crate::api::{self, Body};
use crate::error::ClientResult;
use crate::session::Unlocked;

impl Unlocked {
    /// Tells the server where to push this device's approvals (an APNs
    /// device token, hex). The payload never carries details.
    pub async fn register_push(
        &mut self,
        token: &str,
        environment: PushEnvironment,
    ) -> ClientResult<()> {
        let res = self
            .authed(
                Method::PUT,
                "/v1/devices/current/push",
                &Body::json(&PushRegistration {
                    token: token.to_owned(),
                    environment,
                })?,
            )
            .await?;
        api::empty(res).await
    }

    /// No more pushes to this device.
    pub async fn unregister_push(&mut self) -> ClientResult<()> {
        let res = self
            .authed(Method::DELETE, "/v1/devices/current/push", &Body::Empty)
            .await?;
        api::empty(res).await
    }
}
