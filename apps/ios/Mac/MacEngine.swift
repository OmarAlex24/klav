import Foundation

/// The Mac app's engine (ADR 0027 §3): what the screens share with iOS
/// (`VaultEngine`) plus what only `klavd` does here: its state, unlocking
/// with Touch ID or the password, locking for everyone, and the master
/// password instead of Touch ID on a Mac without it.
///
/// `DaemonEngine` conforms as it is; `SampleEngine` (debug builds only)
/// gives the screenshots a vault without a `klavd`.
protocol MacEngine: VaultEngine {
    func status() -> DaemonInfo
    /// What the unlock's question may say (ADR 0041 §2.4), read on the
    /// held connection the password then goes to.
    func unlockQuestion() throws -> UnlockQuestionInfo
    /// `shown`: the window the question said a typed password opens.
    func unlock(password: String?, shown: PresenceSetting?) throws -> UnlockOutcome
    func lock() throws
    func shutdown() throws
    func decideApprovalWithPassword(id: String, approve: Bool, leaseMinutes: UInt32, requestDigest: String,
                                    password: String?) throws
    func decideTaskWithPassword(id: String, approve: Bool, choice: TaskChoiceInput?, requestDigest: String,
                                password: String?) throws -> TaskItem
    func addToTaskWithPassword(approvalId: String, requestDigest: String, password: String?) throws -> TaskItem
    func fulfillSecretRequestWithPassword(id: String, input: SecretRequestFulfillInput,
                                          password: String?) throws -> SecretRequestFulfillOutput
    func approveAgentWithPassword(id: String, pairingWords: String, projectIds: [String],
                                  expiresInDays: UInt32?, password: String?) throws -> AgentItem

    // «Fix my reused passwords» (ADR 0022 §6): the card, the offer
    // (Touch ID in klavd, or the master password), and each site's progress.
    func reusedOffer(agent: String?) throws -> ReusedOfferInfo
    func offerTaskWithPassword(offer: OfferInput, password: String?) throws -> TaskItem
    func taskProgress(taskId: String) throws -> TaskProgressInfo

    // Development (ADR 0033, ADR 0047): pauses, person-owned labels and the audit log.
    func devAgents() throws -> [DevAgentInfo]
    func setAgentLabel(id: String, label: String?, host: String?) throws
    func pauseAgents(agentId: String?, untilMs: Int64?) throws -> [PauseInfo]
    func resumeAgentsWithPassword(agentId: String?, password: String?) throws -> [PauseInfo]
    // Revoking an agent and changing its grant (ADR 0033, amendment of
    // 2026-11-10): «what it saw», the revocation in two calls and what is
    // left of its key change, the grant in the editor and the sheet of
    // differences. Revoking and narrowing ask nothing; widening asks for
    // Touch ID, or the master password where there is none.
    func agentExposure(id: String) throws -> ExposureInfo
    func revokeAgent(id: String, rotate: Bool) throws -> RevokeReportInfo
    func revokeAgentInBackground(id: String) throws -> RevokeReportInfo?
    func agentRevocations() throws -> [RevocationInfo]
    func grantEditor(id: String) throws -> GrantEditorInfo
    func grantChangePrepare(id: String, change: GrantChangeInput) throws -> GrantChangePreviewInfo
    func grantChangeApplyWithPassword(id: String, change: GrantChangeInput, digest: String,
                                      password: String?) throws -> GrantChangeReportInfo
    func auditLog(filter: LogFilterInput) throws -> [LogEntryInfo]
    func itemActivity(item: String) throws -> ItemActivityInfo
    func auditStatus() throws -> AuditStatusInfo
    func verifyAudit() throws -> VerifyInfo
    // Sandboxes (ADR 0036 E2): the list with its security problem and,
    // when it fails its checks, which one, never `sandbox_list`; and the
    // revocations, signed with the account and without Touch ID (E2.3).
    func sandboxListChecked(allProxies: Bool) throws -> SandboxListCheckedInfo
    func revokeSandbox(proxyId: String, sandboxId: String) throws -> SandboxRevokeInfo
    func revokeAllSandboxes(proxyId: String) throws -> SandboxRevokeInfo
    // The MCP gateway (ADR 0049 §3, §9): Development › MCP servers, and
    // the account's switch, turned on after «update every device first»
    // with Touch ID in klavd or the master password.
    func mcpServers() throws -> McpServersInfo
    func turnMcpGatewayOnWithPassword(everyDeviceUpdated: Bool, password: String?) throws -> Bool
    // The credential proxy on this Mac (ADR 0036 E3.5, layer 11), through
    // its local socket: never klavd, so both work while Klav is locked.
    // Revoking asks nothing and only takes access away (E2.3).
    func localProxy() -> LocalProxyState
    func localProxyRevoke(sandboxId: String?) throws -> LocalRevokeInfo

    // Deleting the account (ADR 0037): Touch ID through klavd where it is
    // set up, the master password in this process. Canceling asks what
    // resuming the agents asks (A2): Touch ID, or the master password.
    func deletionSupported() throws -> Bool
    func requestAccountDeletion(password: String) throws -> AccountDeletionInfo
    func cancelAccountDeletion() throws -> Bool
    func cancelAccountDeletionWithPassword(password: String?) throws -> Bool
    // «Delete this Mac’s copy»: refused while generated passwords that
    // never went up wait, unless `discardUnsent` («Delete anyway», Q3).
    func deleteCopyCheck() throws -> SignOutCheck
    func deleteThisCopy(discardUnsent: Bool) throws

    // The presence gate (ADR 0041, layer 5): the setting, only while
    // unlocked (Q-N2); and each value again with the master password, as
    // the answer to `PresenceRequired`, on the connection that got it.
    func presenceWindow() throws -> PresenceSetting
    func setPresenceWindow(window: PresenceSetting, password: String?) throws -> PresenceSetting
    func presenceCancel()
    func fieldValueWithPassword(id: String, field: String, password: String) throws -> String
    func notesWithPassword(id: String, password: String) throws -> String?
    func totpWithPassword(id: String, password: String) throws -> TotpInfo
    func previousPasswordWithPassword(id: String, index: UInt32, password: String) throws -> String
    func generatedValueWithPassword(createdAt: Int64, password: String) throws -> String
}

extension DaemonEngine: MacEngine {}

extension KlavError {
    /// What to tell the person on the Mac, in the interface's language.
    var macMessage: String {
        switch self {
        case .WrongCredentials: return String(localized: "The master password isn’t right.")
        case .NotLoggedIn: return String(localized: "This Mac doesn’t have an account yet.")
        case .Locked: return String(localized: "Klav is locked.")
        case .SessionExpired: return String(localized: "The session expired or was revoked. Sign in again.")
        case .Network: return String(localized: "Couldn’t reach the server. Check your connection.")
        case .Rollback: return String(localized: "The server sent older data than this Mac has already seen. Nothing was synced: it may be an attack or an old backup.")
        case .Security(let message): return String(localized: "Security problem: \(message)")
        case .BiometryFailed: return String(localized: "Touch ID didn’t finish.")
        case .BiometryUnavailable(let message):
            return message.contains("changed")
                ? String(localized: "Touch ID changed on this Mac. Enter the master password to turn it back on.")
                : String(localized: "Touch ID isn’t available right now: use your master password.")
        case .PasswordRequired: return String(localized: "Enter the master password.")
        case .NotFound(let message): return String(localized: "Not found: \(message)")
        case .Conflict: return String(localized: "The item changed on another device. Sync and try again.")
        // ADR 0041 §2.4. The password window handles `PresenceRequired`;
        // this is what is left when it can't.
        case .PresenceRequired: return String(localized: "Klav needs the master password to show this.")
        case .PresenceBusy(let passwordCheck, let inThisApp, _):
            if passwordCheck {
                return String(localized: "Klav is checking another master password. Try again in a moment.")
            }
            if inThisApp {
                return String(localized: "Klav is already confirming something else in this app. Finish that first.")
            }
            return String(localized: "Another program is asking for Touch ID in Klav. Try again once that prompt closes.")
        case .NotSupported: return String(localized: "Klav’s background service doesn’t offer this. Update Klav.")
        case .ChangedWhileConfirming:
            return String(localized: "The item changed while you confirmed, so Klav didn’t hand anything out. Try again.")
        case .SiteMismatch: return String(localized: "This item isn’t saved for this site.")
        case .Denied(let message): return String(localized: "Not allowed: \(message)")
        case .DaemonUnavailable: return String(localized: "Klav’s background service isn’t running.")
        // ADR 0037 §7.6, §7.7. A person's session never gets
        // `AccountDeleting`: only agents do, and the message says when.
        case .AccountDeleted: return String(localized: "Klav deleted your account")
        case .AccountDeleting(let message): return message
        case .DeletionUnsupported: return String(localized: "This server can’t delete accounts from the app. Ask whoever runs it.")
        case .DeletionAlreadyScheduled: return String(localized: "The deletion of your account is already scheduled. Klav shows when as soon as it syncs.")
        case .DeletionRateLimited: return String(localized: "Klav limits how often the deletion can be asked for. Try again later.")
        case .DeletionNotRecorded(let deleteAt, _):
            guard let deleteAt else {
                return String(localized: "The server canceled the deletion, but this Mac couldn’t save it. It shows after the next sync.")
            }
            return String(localized: "The server scheduled the deletion for \(deletionDay(deleteAt)), but this Mac couldn’t save it. It shows after the next sync.")
        // ADR 0048 §2, §3.2: the invite, in the person's language; a
        // quota, in the server's words (which limit, used, maximum).
        case .InviteInvalid: return String(localized: "This invite code isn’t valid for this email.")
        case .QuotaExceeded(let message): return message
        case .Invalid(let message): return message
        }
    }

    /// Touch ID cannot confirm: the same action goes again with the
    /// master password.
    var wantsPassword: Bool {
        if case .BiometryUnavailable = self { return true }
        if case .PasswordRequired = self { return true }
        return false
    }
}

/// A user-facing message for any error.
func describe(_ error: Error) -> String {
    if let e = error as? KlavError { return e.macMessage }
    return String(localized: "Something went wrong: \(error.localizedDescription)")
}
