import Foundation

/// What the app's screens need from the vault engine (ADR 0027 §3). On iOS
/// it is `KlavCore`, which holds the unlocked account in the app's own
/// process; on macOS it is `DaemonEngine`, a client of `klavd`, so the app,
/// the CLI and the browser extension share one unlocked state.
///
/// Both come from `klav-ffi` with the same method names and labels, so the
/// conformances below are empty. Unlocking, signing in and the device's
/// state differ between the two engines and stay out of the protocol.
///
/// Every call blocks in Rust: run them off the main thread.
protocol VaultEngine: AnyObject, Sendable {
    func sync() throws -> SyncInfo

    // Reading the vault (metadata only, unless the person asks for a value).
    func vaults() throws -> [VaultInfo]
    func projects(vaultId: String?) throws -> [ProjectInfo]
    func setProjectRepos(vaultId: String, projectId: String, repos: [String]) throws -> ProjectInfo
    func items(query: ItemQuery) throws -> [ItemInfo]
    func item(id: String) throws -> ItemDetail
    func fieldValue(id: String, field: String) throws -> String
    func notes(id: String) throws -> String?
    func totp(id: String) throws -> TotpInfo

    // Changing it.
    func createItem(input: NewItemInput) throws -> ItemInfo
    func editItem(id: String, edit: ItemEdit) throws -> ItemInfo
    func trashItem(id: String) throws

    // Password histories (ADR 0022).
    func passwordHistory(id: String) throws -> PasswordHistoryInfo
    func previousPassword(id: String, index: UInt32) throws -> String
    func resolvePending(id: String, accept: Bool) throws -> PasswordHistoryInfo
    func recordGenerated(value: String, host: String?) throws -> Int64
    func generatorHistory() throws -> [GeneratedEntryInfo]
    func generatedValue(createdAt: Int64) throws -> String
    func clearGeneratorHistory() throws -> UInt32

    // Agents: approvals, tasks and registrations (ADR 0014, 0015, 0021).
    // A decision carries the `requestDigest` of the card the person saw:
    // nothing is signed if the request changed since (ADR 0030 §5).
    func approvals() throws -> [ApprovalItem]
    func decideApproval(id: String, approve: Bool, leaseMinutes: UInt32, requestDigest: String) throws
    func tasks() throws -> [TaskItem]
    func decideTask(id: String, approve: Bool, choice: TaskChoiceInput?, requestDigest: String) throws -> TaskItem
    func addToTask(approvalId: String, requestDigest: String) throws -> TaskItem
    func endTask(id: String) throws -> TaskItem
    func secretRequests() throws -> [SecretRequestItem]
    func fulfillSecretRequest(id: String, input: SecretRequestFulfillInput) throws -> SecretRequestFulfillOutput
    func denySecretRequest(id: String, proposalDigest: String) throws -> SecretRequestItem
    func agents() throws -> [AgentItem]
    func approveAgent(id: String, pairingWords: String, projectIds: [String], expiresInDays: UInt32?) throws -> AgentItem
    func denyAgent(id: String) throws

    // Vault health (ADR 0022 §4).
    func vaultHealth() throws -> VaultHealthInfo
    func healthSettings() throws -> HealthSettingsInfo
    func setBreachCheck(on: Bool) throws -> HealthSettingsInfo
}

extension ProjectInfo {
    /// Shortens well-known hosts (`github.com/omar/klav` → `omar/klav`) while
    /// preserving custom Git hosts in full.
    static func shortRepoName(_ normalized: String) -> String {
        for prefix in ["github.com/", "gitlab.com/", "bitbucket.org/"] {
            if normalized.hasPrefix(prefix) {
                return String(normalized.dropFirst(prefix.count))
            }
        }
        return normalized
    }

    /// Short display label for the project's primary linked repository, if any.
    var primaryRepoShort: String? {
        repos.first.map(Self.shortRepoName)
    }

    /// `Vault / Project` or `Vault / Project · owner/repo` when linked.
    var displayWithRepo: String {
        let base = "\(vault) / \(name)"
        guard let repo = primaryRepoShort else { return base }
        let extra = repos.count > 1 ? " +\(repos.count - 1)" : ""
        return "\(base) · \(repo)\(extra)"
    }
}

extension KlavCore: VaultEngine {}
