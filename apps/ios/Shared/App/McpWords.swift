import Foundation

/// The MCP gateway in words (ADR 0049, layer 6), on the iPhone and the Mac:
/// an `ask` card for a tool call, its Face ID / Touch ID reason, the
/// security card, and Activity's «called» and «connected» rows.
///
/// The tool and the local client reach the app only inside their grammars
/// (`A-Z a-z 0-9 _ - .` and `a-z 0-9 -`, checked by `klav-client`), and the
/// profile is the person's own name from the grant they signed. They are
/// still shown as plain text in one line (T136, T260), never as a format
/// or a localization key.
enum McpWords {
    /// The approval is an MCP tool call the card can show.
    static func isToolCall(_ approval: ApprovalItem) -> Bool {
        approval.mcpTool != nil && !approval.security
    }

    /// Who called, according to the proxy: the local client's name, or the
    /// sandbox by the start of its ID. Nil when the proxy named no caller.
    static func caller(localClient: String?, sandboxId: String?) -> String? {
        if let client = localClient { return AgentText.line(client, max: 32) }
        if let sandbox = sandboxId { return String(localized: "sandbox \(AgentText.idPrefix(sandbox))") }
        return nil
    }

    static func caller(_ approval: ApprovalItem) -> String? {
        caller(localClient: approval.localClient, sandboxId: approval.sandboxId)
    }

    /// «For claude-code (according to the proxy)», on a proxied request
    /// that is not a tool call.
    static func callerLine(_ caller: String) -> String {
        String(localized: "For \(caller) (according to the proxy)")
    }

    /// «maple · delete_service», or the tool alone when this device can't
    /// name the profile.
    static func target(profile: String?, tool: String) -> String {
        let tool = AgentText.line(tool, max: 128)
        guard let profile else { return tool }
        return "\(AgentText.line(profile, max: 64)) · \(tool)"
    }

    static func target(_ approval: ApprovalItem) -> String {
        target(profile: approval.mcpProfile, tool: approval.mcpTool ?? "")
    }

    /// «claude-code wants to call maple · delete_service», with the caller
    /// at `Bold.mark(0)` and the target at `Bold.mark(1)` for `sentence`.
    static func wants(hasCaller: Bool) -> String {
        hasCaller ? String(localized: "\(Bold.mark(0)) wants to call \(Bold.mark(1))")
                  : String(localized: "An MCP client wants to call \(Bold.mark(1))")
    }

    /// A notification's or the menu bar's line for an MCP card: who asks
    /// (the caller, or the agent) and «Wants to call maple · delete_service»;
    /// a security card says only that. Nil for any other approval.
    static func summary(_ approval: ApprovalItem) -> (who: String, what: String)? {
        if approval.security {
            return (AgentText.line(approval.agent, max: 40), securityTitle)
        }
        guard isToolCall(approval) else { return nil }
        return (caller(approval) ?? AgentText.line(approval.agent, max: 40),
                String(localized: "Wants to call \(target(approval))"))
    }

    /// What «Approve once» covers (Q6(a), T261).
    static var onceNote: String {
        String(localized: "Approve once: only this call, with these exact arguments. A retry with other arguments asks you again.")
    }

    /// What «Approve 15 min» covers (T261): the tool, with any arguments.
    static var leaseNote: String {
        String(localized: "Approve 15 min: this tool with any arguments, from this caller, for 15 minutes.")
    }

    /// Until sealed arguments exist (ADR 0049 §5.4, a later layer).
    static var argumentsNote: String {
        String(localized: "Arguments aren’t shown yet. Klav checks only that they’re the ones you approve.")
    }

    /// The Face ID / Touch ID reason (T140, T260): fixed text, the profile
    /// and the tool. Never the agent's name or words, nor the caller.
    static func presenceReason(_ approval: ApprovalItem, lease: Bool) -> String {
        let target = target(approval)
        return lease ? String(localized: "Allow \(target) with any arguments for 15 minutes")
                     : String(localized: "Approve one call of \(target)")
    }

    /// The security card's fixed text (T260): nothing the server sent.
    static var securityTitle: String { String(localized: "Security problem") }

    static var securityText: String {
        String(localized: "This request names an MCP tool or a caller in a form Klav never accepts. Your server should have refused it, so there’s nothing to approve here. Check your server, and tell Klav if it keeps happening.")
    }

    /// Which buttons a card shows: none on a security card.
    enum Actions: Equatable { case none, onceAndLease, task }

    static func actions(_ approval: ApprovalItem) -> Actions {
        if approval.security { return .none }
        if approval.task != nil { return .task }
        return .onceAndLease
    }

    // MARK: Activity (ADR 0049 §6)

    /// An MCP row of the log: a tool call, or a session message.
    static func isMcp(_ e: LogEntryInfo) -> Bool { e.mcpTool != nil || e.mcpSession }

    /// Who an MCP row is about: the caller the proxy named, or the
    /// proxy's own name when it named none.
    static func actor(_ e: LogEntryInfo) -> String? {
        guard isMcp(e) else { return nil }
        return caller(localClient: e.localClient, sandboxId: e.sandboxId)
    }

    /// «called maple · query_logs», «connected to maple», «connected to
    /// maple (3 times)».
    static func did(_ e: LogEntryInfo) -> String? {
        if let tool = e.mcpTool {
            return String(localized: "called \(target(profile: e.mcpProfile, tool: tool))")
        }
        guard e.mcpSession else { return nil }
        let times = Int64(e.folded) + 1
        switch (e.mcpProfile.map { AgentText.line($0, max: 64) }, times) {
        case let (profile?, 1): return String(localized: "connected to \(profile)")
        case let (profile?, n): return String(localized: "connected to \(profile) (\(n) times)")
        case (nil, 1): return String(localized: "opened an MCP session")
        case let (nil, n): return String(localized: "opened an MCP session (\(n) times)")
        }
    }

    /// The mark of an MCP row (T136): the caller and the tool are the
    /// proxy's and the server's word.
    static var accordingToProxy: String { String(localized: "according to the proxy") }
}
