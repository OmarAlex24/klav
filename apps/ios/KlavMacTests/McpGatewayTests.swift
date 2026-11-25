import XCTest
@testable import Klav

/// The MCP gateway on the Mac (ADR 0049, layer 6): the approval card of a
/// tool call (caller, profile, tool, what each approval covers), the
/// security card with nothing to decide, the presence reason, Activity's
/// rows and Development › MCP servers, in English and in Spanish.
final class McpGatewayTests: XCTestCase {
    private func es() throws -> Bundle {
        try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
    }

    private func say(_ bundle: Bundle, _ key: String, _ args: CVarArg...) -> String {
        String(format: bundle.localizedString(forKey: key, value: "∅", table: nil), arguments: args)
    }

    private func card(tool: String? = "delete_service", profile: String? = "maple", client: String? = "claude-code",
                      sandbox: String? = nil, security: Bool = false,
                      task: OutsideTaskItem? = nil) -> ApprovalItem {
        ApprovalItem(id: "ap", status: "pending", agentId: "0192f3a4-5b6c-7d8e-9f00-112233445566", agent: "klav-proxy",
                     permission: "proxy", target: "klav://Personal/General/Maple", reason: "MCP call",
                     domain: "api.maple.dev", createdAt: 0, expiresAt: 0, task: task, requestDigest: "d",
                     mcpTool: tool, mcpProfile: profile, localClient: client, sandboxId: sandbox, security: security)
    }

    private func entry(tool: String? = nil, session: Bool = false, profile: String? = "maple",
                       client: String? = "claude-code", sandbox: String? = nil, folded: UInt32 = 0) -> LogEntryInfo {
        LogEntryInfo(seq: 1, atMs: 0, actor: "klav-proxy", byAgent: true, agentId: "0192f3a4-0000", action: "agent.access",
                     permission: "proxy", outcome: "allow", item: nil, itemId: "i", vault: nil, reason: nil,
                     domain: "api.maple.dev", taskId: nil, approvalId: nil, untilMs: nil, attachments: 0, alerts: [],
                     verified: true, mcpTool: tool, mcpProfile: profile, localClient: client, sandboxId: sandbox,
                     mcpSession: session, folded: folded)
    }

    // MARK: The card

    func testAToolCallNamesTheCallerTheProfileAndTheTool() {
        let a = card()
        XCTAssertTrue(McpWords.isToolCall(a))
        XCTAssertEqual(McpWords.caller(a), "claude-code")
        XCTAssertEqual(McpWords.target(a), "maple · delete_service")
        XCTAssertEqual(McpWords.wants(hasCaller: true), "\(Bold.mark(0)) wants to call \(Bold.mark(1))")
        XCTAssertEqual(McpWords.summary(a)?.who, "claude-code")
        XCTAssertEqual(McpWords.summary(a)?.what, "Wants to call maple · delete_service")
        // A sandbox by the start of its ID; the tool alone without a profile.
        let sandboxed = card(profile: nil, client: nil, sandbox: "0193aaaa-bbbb-7ccc-8ddd-eeeeffff0000")
        XCTAssertEqual(McpWords.caller(sandboxed), "sandbox 0193aaaa")
        XCTAssertEqual(McpWords.target(sandboxed), "delete_service")
        // A plain proxied request still names its caller.
        XCTAssertEqual(McpWords.callerLine("claude-code"), "For claude-code (according to the proxy)")
        // Not a tool call: the usual card.
        XCTAssertFalse(McpWords.isToolCall(card(tool: nil)))
        XCTAssertNil(McpWords.summary(card(tool: nil)))
    }

    /// «Approve once» binds the arguments; «Approve 15 min» doesn't (Q6(a),
    /// T261), and the card says so before the person picks.
    func testTheCardSaysWhatEachApprovalCovers() {
        XCTAssertTrue(McpWords.onceNote.contains("only this call, with these exact arguments"))
        XCTAssertTrue(McpWords.leaseNote.contains("this tool with any arguments"))
        XCTAssertEqual(McpWords.actions(card()), .onceAndLease)
        let outside = OutsideTaskItem(id: "t", task: "Deploy", expiresAt: 0, canAdd: false)
        XCTAssertEqual(McpWords.actions(card(task: outside)), .task)
    }

    /// T140, T260: the presence reason is fixed text, profile and tool,
    /// never the agent's name or the caller.
    func testThePresenceReasonIsFixedTextProfileAndTool() {
        let a = card()
        XCTAssertEqual(McpWords.presenceReason(a, lease: false), "Approve one call of maple · delete_service")
        XCTAssertEqual(McpWords.presenceReason(a, lease: true),
                       "Allow maple · delete_service with any arguments for 15 minutes")
        for lease in [false, true] {
            let reason = McpWords.presenceReason(a, lease: lease)
            XCTAssertFalse(reason.contains("klav-proxy"))
            XCTAssertFalse(reason.contains("claude-code"))
            XCTAssertFalse(reason.contains("MCP call"))
        }
    }

    /// T260: a security card shows the fixed text and has nothing to
    /// decide; the model refuses to decide it before any prompt.
    @MainActor
    func testASecurityCardHasNothingToDecide() async throws {
        let bad = card(tool: nil, profile: nil, client: nil, security: true)
        XCTAssertFalse(McpWords.isToolCall(bad))
        XCTAssertEqual(McpWords.actions(bad), .none)
        XCTAssertEqual(McpWords.summary(bad)?.what, "Security problem")
        XCTAssertTrue(McpWords.securityText.hasPrefix("This request names an MCP tool or a caller in a form Klav never accepts."))
        XCTAssertEqual(RequestError.securityCard.userMessage, McpWords.securityText)
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        do {
            try await model.decide(bad, approve: true, leaseMinutes: 0)
            XCTFail("a security card was decided")
        } catch RequestError.securityCard {}
        do {
            try await model.decide(bad, approve: false, leaseMinutes: 0)
            XCTFail("a security card was denied")
        } catch RequestError.securityCard {}
    }

    // MARK: Activity

    /// «claude-code called maple · query_logs» in place of «POST /mcp», and
    /// session rows as «connected to maple», folded.
    func testActivityNamesTheCallerAndTheTool() {
        let call = entry(tool: "query_logs")
        XCTAssertEqual(ActivityWords.actor(call), "claude-code")
        XCTAssertEqual(ActivityWords.did(call), "called maple · query_logs")
        XCTAssertEqual(ActivityWords.did(entry(session: true)), "connected to maple")
        XCTAssertEqual(ActivityWords.did(entry(session: true, folded: 2)), "connected to maple (3 times)")
        XCTAssertEqual(ActivityWords.did(entry(session: true, profile: nil)), "opened an MCP session")
        // A sandbox caller; and the proxy's own name when it named none.
        XCTAssertEqual(ActivityWords.actor(entry(tool: "x", client: nil, sandbox: "0193aaaa-bbbb")), "sandbox 0193aaaa")
        XCTAssertEqual(ActivityWords.actor(entry(tool: "x", client: nil)), "klav-proxy")
        // A plain proxied request keeps the usual words.
        XCTAssertEqual(ActivityWords.actor(entry(client: nil)), "klav-proxy")
        XCTAssertEqual(ActivityWords.did(entry(client: nil)), "used it (proxy)")
    }

    // MARK: MCP servers

    func testTheServersPaneWords() {
        let maple = McpServerInfo(profile: "maple", itemId: "i", title: "Maple", upstream: "https://api.maple.dev",
                                  endpoint: "/mcp", localUrl: "http://127.0.0.1:8790/maple/mcp",
                                  toolsAllow: ["get_*"], toolsAsk: ["delete_*"], toolsDeny: [],
                                  clients: ["claude-code", "my-agent"])
        XCTAssertEqual(McpServersWords.client("claude-code"), "Claude Code")
        XCTAssertEqual(McpServersWords.client("my-agent"), "my-agent")
        XCTAssertNotNil(McpServersWords.clients(maple))
        let on = McpServersInfo(gatewayOn: true, proxy: "klav-proxy", servers: [maple], localClients: [], problems: [])
        XCTAssertEqual(McpServersWords.headerDetail(on), "1 server")
        let off = McpServersInfo(gatewayOn: false, proxy: nil, servers: [], localClients: [], problems: [])
        XCTAssertEqual(McpServersWords.headerDetail(off), "Gateway off")
        let older = McpServersInfo(gatewayOn: nil, proxy: nil, servers: [], localClients: [], problems: [])
        XCTAssertNil(McpServersWords.headerDetail(older))
    }

    /// The sample turns the switch on only with the person's word, then
    /// asks for presence (the master password on a Mac without Touch ID).
    func testTheSwitchNeedsTheWordThenPresence() throws {
        let engine = SampleEngine(locked: false, touchID: false)
        XCTAssertThrowsError(try engine.turnMcpGatewayOnWithPassword(everyDeviceUpdated: false, password: "sample"))
        XCTAssertTrue(try engine.turnMcpGatewayOnWithPassword(everyDeviceUpdated: true, password: "sample"))
        XCTAssertEqual(try engine.mcpServers().gatewayOn, true)
    }

    /// On a Mac without Touch ID, turning the gateway on asks for the
    /// master password over its own sheet, and nothing turns on before it.
    @MainActor
    func testWithoutTouchIDTurningOnAsksForThePasswordOverTheSheet() async throws {
        let engine = SampleEngine(locked: false, touchID: false)
        let model = MacModel.sample(engine)
        model.turningOnMcpGateway = true
        var done = false
        try await model.withPresenceResult("Turn on", host: .mcpGatewaySheet) { engine, password in
            try engine.turnMcpGatewayOnWithPassword(everyDeviceUpdated: true, password: password)
        } done: { _ in done = true }
        let prompt = try XCTUnwrap(model.passwordPrompt)
        XCTAssertEqual(prompt.host, .mcpGatewaySheet)
        XCTAssertNotNil(model.passwordPromptHere(.mcpGatewaySheet).wrappedValue, "shown over the sheet")
        XCTAssertNil(model.passwordPromptHere(.window).wrappedValue, "not over the window under it")
        XCTAssertFalse(done)
        try await prompt.retry("sample")
        XCTAssertTrue(done)
        XCTAssertEqual(try engine.mcpServers().gatewayOn, true)
    }

    // MARK: Spanish

    func testSpanishIsWrittenNatively() throws {
        let es = try es()
        XCTAssertEqual(say(es, "%@ wants to call %@", "claude-code", "maple · delete_service"),
                       "claude-code quiere llamar a maple · delete_service")
        XCTAssertEqual(say(es, "called %@", "maple · query_logs"), "llamó a maple · query_logs")
        XCTAssertEqual(say(es, "connected to %@ (%lld times)", "maple", Int64(3)), "se conectó a maple (3 veces)")
        XCTAssertEqual(say(es, "Approve one call of %@", "maple · delete_service"),
                       "Aprobar una llamada a maple · delete_service")
        XCTAssertEqual(say(es, "mcp.lane.allowed"), "Permitidas")
        XCTAssertEqual(say(es, "mcp.lane.denied"), "Denegadas")
        XCTAssertEqual(say(es, "according to the proxy"), "según el proxy")
        // The keyed lanes read in English too.
        let en = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "en", ofType: "lproj").flatMap(Bundle.init(path:)))
        XCTAssertEqual(say(en, "mcp.lane.ask"), "Asks you")
    }
}
