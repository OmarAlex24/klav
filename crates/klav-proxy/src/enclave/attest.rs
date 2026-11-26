//! The Nitro Secure Module (ADR 0051 §2.2, §5.2): attestation documents on
//! demand and entropy for a new seed.
//!
//! [`AttestationProvider`] is what the enclave needs of it. The real one,
//! [`Nsm`], talks to `/dev/nsm` through AWS's `aws-nitro-enclaves-nsm-api`
//! and exists only on Linux; its `unsafe` lives in that crate, none in
//! Klav's. The tests use a fake with a test P-384 chain (`klav-core`'s
//! `nitro-testkit`), so they run on any machine.

use zeroize::Zeroizing;

/// What a document should carry besides the PCRs.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttestRequest<'a> {
    /// `user_data`: the account's binding (§2.2 step 5).
    pub user_data: Option<&'a [u8]>,
    /// `nonce`: the asker's.
    pub nonce: Option<&'a [u8]>,
    /// `public_key`: a joiner's one-time X25519 key (§4.2 step 1).
    pub public_key: Option<&'a [u8]>,
}

/// The enclave's view of the NSM.
pub trait AttestationProvider: Send + Sync + 'static {
    /// A signed attestation document (`COSE_Sign1`).
    fn attest(&self, request: &AttestRequest<'_>) -> Result<Vec<u8>, String>;

    /// At least 32 bytes of the NSM's entropy, for a new seed.
    fn entropy(&self) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// `/dev/nsm` (Linux, inside an enclave).
#[cfg(target_os = "linux")]
pub struct Nsm {
    fd: i32,
}

#[cfg(target_os = "linux")]
impl Nsm {
    /// Opens `/dev/nsm`.
    pub fn open() -> Result<Self, String> {
        let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
        if fd < 0 {
            return Err("cannot open /dev/nsm: this is not a Nitro Enclave".into());
        }
        Ok(Self { fd })
    }
}

#[cfg(target_os = "linux")]
impl Drop for Nsm {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.fd);
    }
}

#[cfg(target_os = "linux")]
impl AttestationProvider for Nsm {
    fn attest(&self, request: &AttestRequest<'_>) -> Result<Vec<u8>, String> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        // The request holds `serde_bytes::ByteBuf`, which converts from a
        // `Vec<u8>`; the type comes from the request's fields.
        let user_data = request.user_data.map(|b| b.to_vec().into());
        let nonce = request.nonce.map(|b| b.to_vec().into());
        let public_key = request.public_key.map(|b| b.to_vec().into());
        let answer = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(
            self.fd,
            Request::Attestation {
                user_data,
                nonce,
                public_key,
            },
        );
        match answer {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => Err(format!("the NSM refused the attestation: {code:?}")),
            _ => Err("the NSM answered something else".into()),
        }
    }

    fn entropy(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        match aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, Request::GetRandom) {
            Response::GetRandom { random } if random.len() >= 32 => Ok(Zeroizing::new(random)),
            Response::GetRandom { .. } => Err("the NSM gave fewer than 32 bytes".into()),
            Response::Error(code) => Err(format!("the NSM refused entropy: {code:?}")),
            _ => Err("the NSM answered something else".into()),
        }
    }
}

/// A fake NSM for the tests: documents signed by a test chain, with fixed
/// PCRs, at the system clock.
#[cfg(all(test, feature = "enclave-testkit"))]
pub(crate) struct FakeNsm {
    pub(crate) nitro: std::sync::Arc<klav_core::nitro::fake::FakeNitro>,
    pub(crate) pcrs: [klav_core::nitro::Pcr; 4],
}

#[cfg(all(test, feature = "enclave-testkit"))]
impl AttestationProvider for FakeNsm {
    fn attest(&self, request: &AttestRequest<'_>) -> Result<Vec<u8>, String> {
        Ok(self.nitro.attest(&klav_core::nitro::fake::FakeAttestation {
            pcrs: &self.pcrs,
            timestamp_ms: super::now_ms(),
            public_key: request.public_key,
            user_data: request.user_data,
            nonce: request.nonce,
        }))
    }

    fn entropy(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(
            klav_core::crypto::random::array::<32>().to_vec(),
        ))
    }
}
