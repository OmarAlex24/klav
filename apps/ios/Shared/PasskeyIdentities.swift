import AuthenticationServices

/// The passkeys iOS offers in its sheet and in QuickType (ADR 0020 §11):
/// the site, the account and the credential ID, never the key. Signing
/// still goes through the extension and Face ID.
enum PasskeyIdentities {
    /// One identity per passkey; the item ID is the record identifier.
    static func identity(_ p: PasskeyIdentityInfo) -> ASPasskeyCredentialIdentity {
        ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: p.rpId, userName: p.userName.isEmpty ? p.title : p.userName,
            credentialID: p.credentialId, userHandle: p.userHandle, recordIdentifier: p.itemId)
    }

    /// The passkeys for `rpId` exactly (WebAuthn compares the rpId, never a
    /// parent domain), and only those the page allows, if it lists any.
    static func matching(_ all: [PasskeyIdentityInfo], rpId: String, allowed: [Data]) -> [PasskeyIdentityInfo] {
        let rp = rpId.lowercased()
        return all.filter { $0.rpId.lowercased() == rp && (allowed.isEmpty || allowed.contains($0.credentialId)) }
    }

    /// «Suggestions on the keyboard», shared with the app. Off: iOS gets no
    /// identities, neither from the app nor from here.
    static func suggestionsOn(_ defaults: UserDefaults = KlavHome.defaults) -> Bool {
        defaults.object(forKey: "quickType") as? Bool ?? true
    }

    /// Adds a passkey the extension just saved, so iOS offers it at once
    /// (the app replaces the whole list on its next sync).
    static func save(_ p: PasskeyIdentityInfo) async {
        guard suggestionsOn() else { return }
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else { return }
        try? await store.saveCredentialIdentities([identity(p)])
    }
}
