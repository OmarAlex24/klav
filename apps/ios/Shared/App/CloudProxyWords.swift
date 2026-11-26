import Foundation

// Klav Cloud's proxy (ADR 0051 §6.3) in words, for the Mac's Development ›
// Sandboxes and › MCP servers and the iPhone's Settings › Credential proxy.
// Every check runs in `klav-client`; these only say what it found.

/// What the row shows, apart for the tests.
enum CloudProxyWords {
    /// The first seven characters of a commit.
    static func shortCommit(_ commit: String?) -> String {
        String((commit ?? "").prefix(7))
    }

    /// The row's line, or nil when there's nothing to show (an account that
    /// doesn't use it and isn't entitled to it).
    static func headline(_ info: HostedProxyInfo) -> String? {
        switch info.state {
        case .verified:
            return String(localized: "Attested: version \(info.version ?? "?"), commit \(shortCommit(info.commit)), checked just now.")
        case .unverified:
            return String(localized: "Klav Cloud’s proxy couldn’t be verified. Klav won’t share new credentials with it.")
        case .notEntitled:
            return String(localized: "Your account isn’t entitled to Klav Cloud’s proxy any more, so it serves nothing for you.")
        case .lostKeys:
            return String(localized: "Klav Cloud’s proxy lost its keys. Set it up again to keep using your credentials from sandboxes.")
        case .revoked:
            return String(localized: "Klav Cloud’s proxy agent is revoked or gone. Stop using it, or set it up again.")
        case .unreachable:
            return String(localized: "Klav Cloud’s proxy can’t be checked right now. Nothing new is shared with it until it can.")
        case .unsupported:
            return String(localized: "This version of Klav can’t check Klav Cloud’s proxy. Update Klav.")
        case .notUsed:
            guard info.entitled == true else { return nil }
            return String(localized: "Klav Cloud can run your credential proxy in an attested enclave, so sandboxes keep working while your devices are off.")
        }
    }

    /// Why it couldn't be verified, in the person's words (§6.3: say
    /// whether a stale release is likelier than an attack).
    static func reason(_ info: HostedProxyInfo) -> String? {
        guard info.state == .unverified else { return nil }
        switch info.reason {
        case "image_revoked"?:
            return String(localized: "It runs an image Klav revoked. Stop using it, then rotate the provider tokens it held.")
        case "manifest_expired"?:
            return String(localized: "Its list of approved images expired. That’s most likely a late release, not an attack.")
        case "manifest_rollback"?:
            return String(localized: "It served an older list of approved images than this device already checked.")
        case "no_release_key"?:
            return String(localized: "This version of Klav can’t verify it yet.")
        case "other_server"?:
            return String(localized: "It serves accounts of another Klav server.")
        default:
            return String(localized: "Its attestation or its list of approved images doesn’t check out.")
        }
    }

    /// What it means for what it already holds (§6.3).
    static let keeps = String(localized: "What it already holds stays shared until you stop using it. Stopping changes the keys of those credentials; then rotate the tokens at each provider.")

    /// The sheet's text before «Use Klav Cloud Proxy» asks for Touch ID.
    static func useNote(replacesOwn: Bool) -> String {
        replacesOwn
            ? String(localized: "Your devices check the enclave’s attestation before anything is shared. Sandboxes then use Klav Cloud’s proxy; your own proxy keeps its credentials and keeps serving the local agents of the Mac it runs on.")
            : String(localized: "Your devices check the enclave’s attestation before anything is shared. Klav can’t see your credentials: only an enclave running an image Klav published holds them.")
    }

    /// The notes an action left, one line each, in English from klav-client.
    static func notes(_ outcome: HostedProxyOutcomeInfo) -> [String] {
        outcome.notes.map { AgentText.line($0, max: 300) }
    }
}

extension CloudProxyWords {
    /// What the master-password sheet says it's for.
    static func reasonFor(_ action: HostedProxyAction) -> String {
        switch action {
        case .use: return String(localized: "Use Klav Cloud’s proxy as your credential proxy")
        case .stop: return String(localized: "Stop using Klav Cloud’s proxy and change the keys of what it held")
        case .reset: return String(localized: "Set Klav Cloud’s proxy up again and move your credentials to it")
        }
    }
}
