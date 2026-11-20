//! OPAQUE authentication (RFC 9807) with `opaque-ke` (spec §4.5).
//!
//! Cipher suite `klav-opaque-v1`:
//!
//! | Component    | Choice                                        |
//! |--------------|-----------------------------------------------|
//! | OPRF         | ristretto255-SHA512 (RFC 9497)                |
//! | Key exchange | 3DH over ristretto255 with SHA-512            |
//! | KSF          | identity (stretching already done, see below) |
//! | Context      | `"klav/v1/opaque"`                           |
//!
//! The OPAQUE "password" is not the master password: it is the 32-byte
//! [`OpaqueInput`] derived from `Argon2id(password) ⊕ HKDF(Secret Key)` with
//! the label `klav/v1/kdf/opaque` (see [`super::kdf`]). Argon2id therefore
//! runs once, on the client, before OPAQUE, and plays the role of the KSF;
//! running it a second time inside OPAQUE would double the unlock cost and add
//! no security, because the input already carries the 128-bit Secret Key.
//!
//! Neither the OPAQUE export key nor the session key is used: the KEK comes
//! from the KDF (spec §4.3), and the server issues its own session tokens once
//! the login finishes.
//!
//! Both sides live here so that `klav-server` never touches a cryptographic
//! crate directly. None of the types with secret state implement `Debug`,
//! `Display` or `Clone`.

use opaque_ke::ksf::Identity;
use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{
    ClientLoginFinishParameters, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, Ristretto255, ServerLoginParameters, ServerRegistration, TripleDh,
};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::keys::KEY_LEN;
use super::{CryptoError, random};

/// OPAQUE context string (binds the transcript to Klav v1).
pub const CONTEXT: &[u8] = b"klav/v1/opaque";

/// Name of the cipher suite, for documentation and diagnostics.
pub const SUITE_NAME: &str = "klav-opaque-v1";

/// The `opaque-ke` cipher suite of Klav v1.
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_v010::Sha512>;
    type Ksf = Identity;
}

/// The operating system CSPRNG behind the `rand_core` 0.6 traits that
/// `opaque-ke` expects.
struct OsRng;

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(random::array())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(random::array())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        random::fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        random::fill(dest);
        Ok(())
    }
}

impl CryptoRng for OsRng {}

fn identifiers() -> Identifiers<'static> {
    // Default identities: the client and server public keys (RFC 9807 §4.1.2).
    Identifiers {
        client: None,
        server: None,
    }
}

/// The secret input to OPAQUE, derived by
/// [`super::kdf::derive_account_keys`]. Zeroized on drop.
pub struct OpaqueInput(SecretBox<[u8; KEY_LEN]>);

impl OpaqueInput {
    pub(crate) fn from_secret(bytes: SecretBox<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }

    /// Builds an input from raw bytes. Only for tests.
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    pub fn from_bytes_for_tests(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    fn bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

fn protocol<T, E>(result: Result<T, E>) -> Result<T, CryptoError> {
    result.map_err(|_| CryptoError::Opaque)
}

// ------------------------------------------------------------------ client --

/// Client state between the two registration messages.
pub struct ClientRegistration(opaque_ke::ClientRegistration<Suite>);

/// Starts a registration. Returns the state and the `RegistrationRequest`
/// to send to the server.
pub fn client_start_registration(
    input: &OpaqueInput,
) -> Result<(ClientRegistration, Vec<u8>), CryptoError> {
    let start = protocol(opaque_ke::ClientRegistration::<Suite>::start(
        &mut OsRng,
        input.bytes(),
    ))?;
    Ok((
        ClientRegistration(start.state),
        start.message.serialize().to_vec(),
    ))
}

impl ClientRegistration {
    /// Processes the server's `RegistrationResponse` and returns the
    /// `RegistrationUpload` (the record the server stores).
    pub fn finish(self, input: &OpaqueInput, response: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let response = protocol(RegistrationResponse::<Suite>::deserialize(response))?;
        let finish = protocol(self.0.finish(
            &mut OsRng,
            input.bytes(),
            response,
            ClientRegistrationFinishParameters::new(identifiers(), None),
        ))?;
        Ok(finish.message.serialize().to_vec())
    }
}

/// Client state between the two login messages.
pub struct ClientLogin(opaque_ke::ClientLogin<Suite>);

/// Starts a login. Returns the state and the `CredentialRequest` (KE1).
pub fn client_start_login(input: &OpaqueInput) -> Result<(ClientLogin, Vec<u8>), CryptoError> {
    let start = protocol(opaque_ke::ClientLogin::<Suite>::start(
        &mut OsRng,
        input.bytes(),
    ))?;
    Ok((ClientLogin(start.state), start.message.serialize().to_vec()))
}

impl ClientLogin {
    /// Processes the server's `CredentialResponse` (KE2) and returns the
    /// `CredentialFinalization` (KE3). Fails with [`CryptoError::Opaque`] on a
    /// wrong password, an unknown account or a tampered response.
    pub fn finish(self, input: &OpaqueInput, response: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let response = protocol(CredentialResponse::<Suite>::deserialize(response))?;
        let finish = protocol(self.0.finish(
            &mut OsRng,
            input.bytes(),
            response,
            ClientLoginFinishParameters::new(Some(CONTEXT), identifiers(), None),
        ))?;
        Ok(finish.message.serialize().to_vec())
    }
}

// ------------------------------------------------------------------ server --

/// Long-term server keys: the OPRF seed and the server's key-exchange key
/// pair. Generated once and persisted by the server.
pub struct ServerSetup(opaque_ke::ServerSetup<Suite>);

impl ServerSetup {
    /// Generates fresh server keys from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(opaque_ke::ServerSetup::<Suite>::new(&mut OsRng))
    }

    /// Serialized form, for persistence. Contains private keys.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        use zeroize::Zeroize as _;
        let mut keys = self.0.serialize();
        let out = Zeroizing::new(keys.to_vec());
        keys.as_mut_slice().zeroize();
        out
    }

    /// Restores serialized server keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        protocol(opaque_ke::ServerSetup::<Suite>::deserialize(bytes)).map(Self)
    }
}

/// Answers a `RegistrationRequest`. `credential_id` is the server-side
/// account identifier (the normalised e-mail); the same value must be used at
/// login, because it selects the per-account OPRF key.
pub fn server_registration_response(
    setup: &ServerSetup,
    request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let request = protocol(RegistrationRequest::<Suite>::deserialize(request))?;
    let start = protocol(ServerRegistration::<Suite>::start(
        &setup.0,
        request,
        credential_id,
    ))?;
    Ok(start.message.serialize().to_vec())
}

/// Turns the client's `RegistrationUpload` into the record to store (the
/// OPAQUE "password file"). The record cannot be attacked offline without
/// the Secret Key, because the OPAQUE input includes it.
pub fn server_registration_record(upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let upload = protocol(RegistrationUpload::<Suite>::deserialize(upload))?;
    Ok(ServerRegistration::<Suite>::finish(upload)
        .serialize()
        .to_vec())
}

/// Server state between the two login messages (contains the expected
/// client MAC and ephemeral keys).
pub struct ServerLogin(opaque_ke::ServerLogin<Suite>);

/// Answers a `CredentialRequest` (KE1) with a `CredentialResponse` (KE2).
///
/// When `record` is `None` (unknown account) `opaque-ke` answers with a
/// decoy response that is indistinguishable from a real one; the login then
/// fails at [`ServerLogin::finish`], exactly like a wrong password.
pub fn server_start_login(
    setup: &ServerSetup,
    record: Option<&[u8]>,
    request: &[u8],
    credential_id: &[u8],
) -> Result<(ServerLogin, Vec<u8>), CryptoError> {
    let record = match record {
        Some(bytes) => Some(protocol(ServerRegistration::<Suite>::deserialize(bytes))?),
        None => None,
    };
    let request = protocol(CredentialRequest::<Suite>::deserialize(request))?;
    let start = protocol(opaque_ke::ServerLogin::start(
        &mut OsRng,
        &setup.0,
        record,
        request,
        credential_id,
        ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: identifiers(),
        },
    ))?;
    Ok((ServerLogin(start.state), start.message.serialize().to_vec()))
}

impl ServerLogin {
    /// Verifies the client's `CredentialFinalization` (KE3). Success proves
    /// the client knows the OPAQUE input of the account.
    pub fn finish(self, finalization: &[u8]) -> Result<(), CryptoError> {
        let finalization = protocol(CredentialFinalization::<Suite>::deserialize(finalization))?;
        protocol(self.0.finish(
            finalization,
            ServerLoginParameters {
                context: Some(CONTEXT),
                identifiers: identifiers(),
            },
        ))
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(OpaqueInput: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ServerSetup: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ServerLogin: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ClientLogin: std::fmt::Debug, std::fmt::Display, Clone);
    static_assertions::assert_not_impl_any!(ClientRegistration: std::fmt::Debug, std::fmt::Display, Clone);

    const ID: &[u8] = b"ana@example.com";

    fn register(setup: &ServerSetup, input: &OpaqueInput, id: &[u8]) -> Vec<u8> {
        let (state, request) = client_start_registration(input).unwrap();
        let response = server_registration_response(setup, &request, id).unwrap();
        let upload = state.finish(input, &response).unwrap();
        server_registration_record(&upload).unwrap()
    }

    fn login(
        setup: &ServerSetup,
        record: Option<&[u8]>,
        input: &OpaqueInput,
        id: &[u8],
    ) -> Result<(), CryptoError> {
        let (client, ke1) = client_start_login(input)?;
        let (server, ke2) = server_start_login(setup, record, &ke1, id)?;
        let ke3 = client.finish(input, &ke2)?;
        server.finish(&ke3)
    }

    #[test]
    fn register_then_login() {
        let setup = ServerSetup::generate();
        let input = OpaqueInput::from_bytes_for_tests([1; KEY_LEN]);
        let record = register(&setup, &input, ID);
        assert_eq!(login(&setup, Some(&record), &input, ID), Ok(()));

        // The setup survives a serialization round-trip.
        let restored = ServerSetup::from_bytes(&setup.to_bytes()).unwrap();
        assert_eq!(login(&restored, Some(&record), &input, ID), Ok(()));
    }

    #[test]
    fn wrong_input_unknown_account_and_wrong_identifier_fail() {
        let setup = ServerSetup::generate();
        let input = OpaqueInput::from_bytes_for_tests([1; KEY_LEN]);
        let record = register(&setup, &input, ID);
        let wrong = OpaqueInput::from_bytes_for_tests([2; KEY_LEN]);
        assert_eq!(
            login(&setup, Some(&record), &wrong, ID),
            Err(CryptoError::Opaque)
        );
        assert_eq!(login(&setup, None, &input, ID), Err(CryptoError::Opaque));
        assert_eq!(
            login(&setup, Some(&record), &input, b"bob@example.com"),
            Err(CryptoError::Opaque)
        );
        // Another server's keys do not accept the record.
        assert_eq!(
            login(&ServerSetup::generate(), Some(&record), &input, ID),
            Err(CryptoError::Opaque)
        );
    }

    #[test]
    fn tampered_finalization_is_rejected() {
        let setup = ServerSetup::generate();
        let input = OpaqueInput::from_bytes_for_tests([3; KEY_LEN]);
        let record = register(&setup, &input, ID);
        let (client, ke1) = client_start_login(&input).unwrap();
        let (server, ke2) = server_start_login(&setup, Some(&record), &ke1, ID).unwrap();
        let mut ke3 = client.finish(&input, &ke2).unwrap();
        ke3[0] ^= 1;
        assert_eq!(server.finish(&ke3), Err(CryptoError::Opaque));
    }

    #[test]
    fn garbage_messages_are_rejected() {
        let setup = ServerSetup::generate();
        assert!(server_registration_response(&setup, &[0; 3], ID).is_err());
        assert!(server_registration_record(&[0; 3]).is_err());
        assert!(server_start_login(&setup, None, &[0; 3], ID).is_err());
        assert!(server_start_login(&setup, Some(&[0; 3]), &[0; 96], ID).is_err());
        assert!(ServerSetup::from_bytes(&[0; 3]).is_err());
    }
}
