import AuthenticationServices
import Foundation

/// A passkey registration iOS asked for (ADR 0020 §11). iOS already
/// checked the rpId against the site; klav-core checks its form again.
struct PasskeyAsk: Equatable {
    var rpId: String
    var userName: String
    var userHandle: Data
    var clientDataHash: Data
    /// `excludeCredentials`: the site's passkeys for this account.
    var exclude: [Data]
}

/// What iOS asked the extension for.
enum CredentialAsk {
    /// The person opened Klav from the AutoFill menu (passwords).
    case passwords(services: [String])
    /// The same, for a one-time code field (iOS 18).
    case codes(services: [String])
    /// A QuickType suggestion was picked: this item, for this service.
    case password(id: String, service: String)
    case code(id: String, service: String)
    /// The list, for a page that asked for a passkey: the site's passkeys
    /// in Klav first, then its logins.
    case passkeys(services: [String], rpId: String, clientDataHash: Data, allowed: [Data])
    /// A passkey picked in the system's sheet or QuickType: sign with it.
    case passkey(rpId: String, credentialId: Data, clientDataHash: Data)
    /// Save a new passkey, without network (ADR 0020 §11).
    case register(PasskeyAsk)

    var services: [String] {
        switch self {
        case .passwords(let s), .codes(let s): return s
        case .password(_, let s), .code(_, let s): return [s]
        case .passkeys(let s, let rp, _, _): return s.isEmpty ? [rp] : s
        case .passkey(let rp, _, _): return [rp]
        case .register(let a): return [a.rpId]
        }
    }

    var isPasskey: Bool {
        switch self {
        case .passkeys, .passkey, .register: return true
        default: return false
        }
    }

    var wantsCode: Bool {
        switch self {
        case .codes, .code: return true
        default: return false
        }
    }
}

/// The logins offered for the site (ADR 0025 §3): the site's own, exact
/// host first and then its subdomains; and, apart, the ones saved for a
/// subdomain of the page («Saved for a subdomain»), only filled when the
/// person picks one.
struct Listed: Equatable {
    /// The site's passkeys in Klav (only for a page that asked for one).
    var passkeys: [PasskeyIdentityInfo] = []
    var logins: [ItemInfo] = []
    var parent: [ParentSuggestion] = []

    var isEmpty: Bool { passkeys.isEmpty && logins.isEmpty && parent.isEmpty }
}

/// The extension's state: Face ID unlock, then the logins for the site.
/// It never derives the key from the master password (Argon2id needs far
/// more memory than iOS gives AutoFill) and never syncs: it reads what the
/// app last saved.
@MainActor
final class CredentialModel: ObservableObject {
    enum Phase: Equatable {
        case locked
        case unlocking
        /// Only the app can unlock now (no Face ID, or it wants the password).
        case needsApp(String)
        case list(Listed)
        case filling
        /// The account already has a passkey in this login: replace it?
        case replace(title: String)
    }

    @Published private(set) var phase: Phase = .locked
    @Published private(set) var problem: String?
    @Published private(set) var ask: CredentialAsk = .passwords(services: [])
    /// Signing in with a passkey right now (the wait says so).
    @Published private(set) var signing = false

    private weak var context: ASCredentialProviderExtensionContext?
    private var service: CoreService?
    private var started = false
    private var appeared = false
    /// The sheet went away (dismissed, or the app below went to the
    /// background): the keys are dropped, and an unlock that finishes
    /// later drops them again.
    private var gone = false
    /// The service each listed item matched (what `choose` fills for).
    private var matched: [String: String] = [:]

    init(context: ASCredentialProviderExtensionContext?) {
        self.context = context
    }

    func attach(_ context: ASCredentialProviderExtensionContext) {
        self.context = context
    }

    /// The site the request is for, as the person reads it.
    var host: String? {
        for s in ask.services {
            if let host = try? serviceHost(service: s) { return host }
        }
        return ask.services.first
    }

    func begin(_ ask: CredentialAsk) {
        self.ask = ask
        Footprint.note("begin")
        do {
            service = try CoreService()
        } catch {
            phase = .needsApp(describe(error))
            return
        }
        guard let service else { return }
        let status = service.core.status()
        guard status.hasAccount else {
            phase = .needsApp(String(localized: "Open the Klav app and sign in on this iPhone."))
            return
        }
        let face = service.core.biometricState(keystore: service.keystore)
        if !face.available || !face.enrolled {
            phase = .needsApp(String(localized: "Turn on Face ID in the Klav app’s Settings to fill from here."))
        } else if let reason = face.passwordRequired {
            phase = .needsApp(String(localized: "Face ID asks for the master password \(passwordReason(reason)). Open the Klav app and unlock it, then fill again."))
        }
        offerFaceID()
    }

    /// The sheet is on screen (this may come before or after iOS's request).
    func appear() {
        appeared = true
        gone = false
        offerFaceID()
    }

    /// The sheet is off screen, or the app it fills for left the screen:
    /// lock, so the keys do not stay in memory while the extension lives
    /// on. Coming back shows the Face ID button again.
    func disappear() {
        gone = true
        finish()
        matched = [:]
        switch phase {
        case .list, .filling, .unlocking, .replace: phase = .locked
        case .locked, .needsApp: break
        }
    }

    /// Shows the Face ID prompt once, when both the sheet and the request
    /// are there.
    private func offerFaceID() {
        guard appeared, !started, service != nil, phase == .locked else { return }
        started = true
        Task {
            // The sheet must finish sliding in before iOS shows Face ID.
            try? await Task.sleep(for: .milliseconds(450))
            unlock(auto: true)
        }
    }

    func unlock(auto: Bool = false) {
        guard let service, phase == .locked || phase == .unlocking else { return }
        // The automatic try waits for the sheet; it may have left by then.
        // The button is pressed on screen.
        if auto, gone { return }
        gone = false
        phase = .unlocking
        problem = nil
        // What Face ID says it is for.
        let reason: String
        switch ask {
        case .register: reason = String(localized: "Save a passkey with Klav")
        case .passkey, .passkeys: reason = String(localized: "Sign in with Klav")
        default: reason = String(localized: "Fill with Klav")
        }
        Task {
            do {
                try await service.run { core, keystore in
                    try core.unlockWithBiometrics(keystore: keystore, reason: reason)
                }
                Footprint.note("unlocked")
                if gone {
                    // The sheet left while Face ID was up.
                    finish()
                    phase = .locked
                    return
                }
                await afterUnlock()
            } catch KlavError.BiometryFailed {
                phase = .locked
            } catch KlavError.BiometryUnavailable(let message) {
                phase = .locked
                // The automatic try can come too early; the button retries.
                if !auto {
                    problem = message.contains("changed")
                        ? KlavError.BiometryUnavailable(message: message).userMessage
                        : String(localized: "Face ID isn’t available right now. Try again or open the Klav app.")
                }
            } catch KlavError.PasswordRequired(let reason) {
                phase = .needsApp(String(localized: "Face ID asks for the master password \(passwordReason(reason)). Open the Klav app and unlock it, then fill again."))
            } catch {
                phase = .locked
                problem = describe(error)
            }
        }
    }

    private func afterUnlock() async {
        switch ask {
        case .password(let id, let service), .code(let id, let service):
            await fill(id: id, service: service)
        case .passwords, .codes, .passkeys:
            await loadList()
        case .passkey(let rp, let credential, let hash):
            await signIn(rpId: rp, credentialId: credential, clientDataHash: hash)
        case .register(let request):
            await register(request, replace: false)
        }
    }

    private func loadList() async {
        guard let service else { return }
        let services = ask.services
        let codes = ask.wantsCode
        let passkeysFor: (rp: String, allowed: [Data])? = {
            if case .passkeys(_, let rp, _, let allowed) = ask { return (rp, allowed) }
            return nil
        }()
        do {
            let (found, passkeys) = try await service.run { core, _ -> (SiteMatches, [PasskeyIdentityInfo]) in
                var matches = SiteMatches()
                // The site's own logins first, in klav-core's order (exact,
                // then subdomain); a login that matches one service is never
                // also offered as a parent's.
                for s in services {
                    matches.add((try? core.suggestions(service: s)) ?? [], for: s)
                }
                for s in services {
                    matches.addParent((try? core.parentSuggestions(service: s)) ?? [], for: s)
                }
                if codes {
                    let withCodes = Set(try core.credentialIdentities().filter(\.hasTotp).map(\.itemId))
                    matches.keep { withCodes.contains($0.id) }
                }
                let passkeys = try passkeysFor.map {
                    PasskeyIdentities.matching(try core.passkeyIdentities(), rpId: $0.rp, allowed: $0.allowed)
                } ?? []
                return (matches, passkeys)
            }
            guard !gone else { return }
            Footprint.note("listed \(passkeys.count)+\(found.items.count)+\(found.parent.count)")
            matched = found.services
            phase = .list(Listed(passkeys: passkeys, logins: found.items, parent: found.parent))
        } catch {
            // Locked because the sheet left: the button unlocks again.
            if gone { phase = .locked; return }
            problem = describe(error)
            phase = .list(Listed())
        }
    }

    /// The live code of an item in the list (codes only).
    var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let service = service
        return { id in
            guard let service else { throw CancellationError() }
            return try await service.run { core, _ in try core.totp(id: id) }
        }
    }

    /// The person picked a login from the list. `savedFor`: from the
    /// «Saved for a subdomain» group (ADR 0025), the host it was saved for.
    func choose(_ item: ItemInfo, savedFor: String? = nil) {
        // The service this item matched, also in the parent group; the
        // list only has matched items.
        guard let service = matched[item.id] else { return }
        Task {
            let filled = await fill(id: item.id, service: service, chosen: savedFor != nil)
            // The extension does not write the vault: the app offers to add
            // this site to the item next time it opens.
            if filled, let savedFor, let host = try? serviceHost(service: service) {
                SiteOffer.leave(SiteOffer(itemId: item.id, title: item.title, host: host, savedFor: savedFor, at: Date()))
            }
        }
    }

    /// Fills `id` for `site`. `chosen`: the person picked it in the
    /// «Saved for a subdomain» group, which klav-core accepts only then;
    /// QuickType (`.password`, `.code`) never sets it. Returns whether the
    /// request was completed.
    @discardableResult
    private func fill(id: String, service site: String, chosen: Bool = false) async -> Bool {
        guard let service else { return false }
        phase = .filling
        problem = nil
        do {
            if ask.wantsCode {
                let code = try await service.run { core, _ in try core.oneTimeCode(id: id, service: site, chosen: chosen) }
                Footprint.note("code")
                finish()
                _ = await context?.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code.code))
            } else {
                let credential = try await service.run { core, _ in try core.passwordCredential(id: id, service: site, chosen: chosen) }
                Footprint.note("password")
                finish()
                context?.completeRequest(withSelectedCredential: ASPasswordCredential(
                    user: credential.username, password: credential.password))
            }
            return true
        } catch _ where gone {
            // The sheet left mid-fill and the vault locked: start over.
            phase = .locked
        } catch KlavError.SiteMismatch {
            let site = host ?? String(localized: "this site")
            await loadList()
            // A login of the parent group is in the list now, with its
            // saved host: no need to say it is for another site.
            if case .list(let listed) = phase, listed.parent.contains(where: { $0.item.id == id }) {
                problem = nil
            } else {
                problem = String(localized: "This item isn’t saved for \(site). Klav doesn’t fill it on another site.")
            }
        } catch {
            problem = describe(error)
            await loadList()
        }
        return false
    }

    func cancel() {
        finish()
        context?.cancelRequest(withError: ASExtensionError(.userCanceled))
    }

    // MARK: Passkeys (ADR 0020 §11)

    /// The person picked a passkey from the list.
    func choose(_ passkey: PasskeyIdentityInfo) {
        guard case .passkeys(_, let rp, let hash, _) = ask else { return }
        Task { await signIn(rpId: rp, credentialId: passkey.credentialId, clientDataHash: hash) }
    }

    /// Signs over the `clientDataHash` iOS built. Face ID opened the
    /// extension: the authenticator data says the user was verified. No
    /// network: `passkey.used` waits in the outbox for the app.
    private func signIn(rpId: String, credentialId: Data, clientDataHash: Data) async {
        guard let service else { return }
        phase = .filling
        signing = true
        defer { signing = false }
        problem = nil
        do {
            let a = try await service.run { core, _ in
                try core.passkeyAssertion(rpId: rpId, credentialId: credentialId, clientDataHash: clientDataHash)
            }
            Footprint.note("passkey")
            finish()
            _ = await context?.completeAssertionRequest(using: ASPasskeyAssertionCredential(
                userHandle: a.userHandle, relyingParty: rpId, signature: a.signature,
                clientDataHash: clientDataHash, authenticatorData: a.authenticatorData,
                credentialID: a.credentialId))
        } catch _ where gone {
            phase = .locked
        } catch KlavError.NotFound {
            // Gone since iOS listed it (deleted on another device, then synced).
            finish()
            context?.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
        } catch {
            if case .passkeys = ask {
                problem = describe(error)
                await loadList()
            } else {
                // Picked in iOS's sheet: no list to go back to. Locked
                // again, with the reason; the button tries again.
                finish()
                phase = .locked
                problem = describe(error)
            }
        }
    }

    /// Saves a new passkey on this iPhone, usable at once, and hands it to
    /// the page; the app uploads it when it opens (the sheet said so before
    /// Face ID). `replace`: the person said yes to replacing the account's
    /// passkey in that login.
    private func register(_ request: PasskeyAsk, replace: Bool) async {
        guard let service else { return }
        phase = .filling
        problem = nil
        let input = PasskeyRegistrationInput(
            rpId: request.rpId, rpName: nil, userName: request.userName, userDisplayName: nil,
            userHandle: request.userHandle, excludeCredentials: request.exclude,
            itemId: nil, replace: replace, vault: nil, project: nil)
        do {
            let outcome = try await service.run { core, _ in try core.passkeyRegistration(input: input) }
            switch outcome {
            case .excluded:
                finish()
                context?.cancelRequest(withError: ASExtensionError(.matchedExcludedCredential))
            case .exists(_, let title):
                guard !gone else { phase = .locked; return }
                phase = .replace(title: title)
            case .created(let credentialId, let attestationObject, _, let itemId, let title):
                Footprint.note("passkey saved")
                finish()
                await PasskeyIdentities.save(PasskeyIdentityInfo(
                    itemId: itemId, title: title, rpId: request.rpId, userName: request.userName,
                    credentialId: credentialId, userHandle: request.userHandle))
                _ = await context?.completeRegistrationRequest(using: ASPasskeyRegistrationCredential(
                    relyingParty: request.rpId, clientDataHash: request.clientDataHash,
                    credentialID: credentialId, attestationObject: attestationObject))
            }
        } catch _ where gone {
            phase = .locked
        } catch {
            // Locked again: the button retries.
            finish()
            phase = .locked
            problem = describe(error)
        }
    }

    /// «Replace» or «Keep it» for the account's passkey in that login.
    func answerReplace(_ yes: Bool) {
        guard case .register(let request) = ask, case .replace = phase else { return }
        guard yes else { cancel(); return }
        Task { await register(request, replace: true) }
    }

    /// Drops the keys before handing control back.
    private func finish() {
        service?.core.lock()
    }
}
