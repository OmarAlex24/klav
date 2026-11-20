import AuthenticationServices

/// The suggestions iOS shows in the QuickType bar (ADR 0018 §4): for each
/// login with a site, its user name (or title) and the site; and each
/// passkey, synced or still waiting in the outbox (ADR 0020 §11). No
/// secrets: filling still goes through the extension and Face ID.
enum IdentityStore {
    static func replace(with identities: [CredentialIdentity], passkeys: [PasskeyIdentityInfo] = []) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else { return }
        let out = suggestions(for: identities) + passkeys.map(PasskeyIdentities.identity)
        do {
            try await store.replaceCredentialIdentities(out)
            appLog.info("quicktype: \(out.count, privacy: .public) identities")
        } catch {
            appLog.error("quicktype: \(error.localizedDescription, privacy: .private)")
        }
    }

    /// One password suggestion per site of a login with a password, and one
    /// code suggestion per site of a login with a TOTP seed.
    static func suggestions(for identities: [CredentialIdentity]) -> [any ASCredentialIdentity] {
        var out: [any ASCredentialIdentity] = []
        for identity in identities {
            for host in identity.hosts {
                let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                if identity.hasPassword {
                    out.append(ASPasswordCredentialIdentity(
                        serviceIdentifier: service,
                        user: identity.username.isEmpty ? identity.title : identity.username,
                        recordIdentifier: identity.itemId))
                }
                if identity.hasTotp {
                    out.append(ASOneTimeCodeCredentialIdentity(
                        serviceIdentifier: service, label: identity.title, recordIdentifier: identity.itemId))
                }
            }
        }
        return out
    }

    static func clear() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}
