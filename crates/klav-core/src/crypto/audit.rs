//! The audit log's hash chain and the signed chain heads (design §6, spec
//! §13.7).
//!
//! ```text
//! hash_0 = 32 zero bytes
//! hash_n = SHA-256(tuple("klav/v1/audit/event", u64(n), hash_{n-1}, event_n))
//! head   = Ed25519 over tuple("klav/v1/sig/audit-head", account_id, u64(n), hash_n)
//! ```
//!
//! `event_n` are the exact JSON bytes the server stored. A trusted device
//! that verified the chain up to `n` signs the head; a server that later
//! rewrites, drops or reorders an earlier event no longer reaches that hash.

use sha2::{Digest, Sha256};

use super::CryptoError;
use super::encoding::Tuple;
use super::identity::{IdentityKeyPair, PublicIdentity};
use super::sign::{self, Signature};
use crate::ids::AccountId;

/// Label of a chain link.
pub const LABEL_EVENT: &str = "klav/v1/audit/event";
/// Label of a signed chain head.
pub const LABEL_HEAD: &str = "klav/v1/sig/audit-head";
/// Hash before the first event.
pub const GENESIS: [u8; 32] = [0; 32];

/// `hash_n` from `hash_{n-1}` and the bytes of event `n`.
pub fn chain_hash(seq: u64, previous: &[u8; 32], event: &[u8]) -> [u8; 32] {
    let mut tuple = Tuple::new(LABEL_EVENT);
    tuple.push_u64(seq).push(previous).push(event);
    Sha256::digest(tuple.as_bytes()).into()
}

/// Signs the chain head `(seq, hash)` with the account identity.
pub fn sign_head(
    account: &IdentityKeyPair,
    account_id: AccountId,
    seq: u64,
    hash: &[u8; 32],
) -> Signature {
    sign::sign(
        account,
        LABEL_HEAD,
        &[account_id.as_bytes(), &seq.to_be_bytes(), hash],
    )
    .expect("valid label")
}

/// Verifies a signed chain head.
pub fn verify_head(
    account: &PublicIdentity,
    account_id: AccountId,
    seq: u64,
    hash: &[u8; 32],
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_HEAD,
        &[account_id.as_bytes(), &seq.to_be_bytes(), hash],
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_changes() {
        let h1 = chain_hash(1, &GENESIS, b"{\"a\":1}");
        let h2 = chain_hash(2, &h1, b"{\"b\":2}");
        assert_ne!(chain_hash(1, &GENESIS, b"{\"a\":2}"), h1);
        assert_ne!(chain_hash(2, &GENESIS, b"{\"b\":2}"), h2);
        assert_ne!(chain_hash(3, &h1, b"{\"b\":2}"), h2);
        let keys = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let sig = sign_head(&keys, account, 2, &h2);
        verify_head(keys.public(), account, 2, &h2, &sig).unwrap();
        assert!(verify_head(keys.public(), account, 1, &h2, &sig).is_err());
        assert!(verify_head(keys.public(), account, 2, &h1, &sig).is_err());
    }
}
