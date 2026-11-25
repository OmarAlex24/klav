import XCTest
@testable import Klav

/// The MCP gateway on the iPhone (ADR 0049, layer 6): the approval card's
/// words, the Face ID reason (T140, T260), the security card, and the
/// Activity rows, with their Spanish.
final class McpCardTests: XCTestCase {
    private func card(security: Bool = false) -> ApprovalItem {
        ApprovalItem(id: "ap", status: "pending", agentId: "0192f3a4-5b6c-7d8e-9f00-112233445566", agent: "klav-proxy",
                     permission: "proxy", target: "klav://Personal/General/Maple", reason: "MCP call",
                     domain: nil, createdAt: 0, expiresAt: 0, task: nil, requestDigest: "d",
                     mcpTool: security ? nil : "delete_service", mcpProfile: security ? nil : "maple",
                     localClient: security ? nil : "claude-code", security: security)
    }

    func testTheCardAndFaceIDNameOnlyProfileAndTool() {
        let a = card()
        XCTAssertTrue(McpWords.isToolCall(a))
        XCTAssertEqual(McpWords.caller(a), "claude-code")
        XCTAssertEqual(McpWords.presenceReason(a, lease: false), "Approve one call of maple · delete_service")
        XCTAssertFalse(McpWords.presenceReason(a, lease: true).contains("klav-proxy"))
        let bad = card(security: true)
        XCTAssertEqual(McpWords.actions(bad), .none)
        XCTAssertFalse(McpWords.isToolCall(bad))
    }

    @MainActor
    func testASecurityCardIsNeverDecided() async {
        let model = AppModel()
        do {
            try await model.decide(card(security: true), approve: true)
            XCTFail("decided")
        } catch {
            XCTAssertEqual(error as? RequestError, .securityCard)
        }
    }

    func testActivityRows() throws {
        let call = LogEntryInfo(seq: 1, atMs: 0, actor: "klav-proxy", byAgent: true, agentId: "a", action: "agent.access",
                                permission: "proxy", outcome: "allow", item: nil, itemId: nil, vault: nil, reason: nil,
                                domain: nil, taskId: nil, approvalId: nil, untilMs: nil, attachments: 0, alerts: [],
                                verified: true, mcpTool: "query_logs", mcpProfile: "maple", localClient: "claude-code")
        XCTAssertEqual(ActivityWords.actor(call), "claude-code")
        XCTAssertEqual(ActivityWords.did(call), "called maple · query_logs")
        let es = try XCTUnwrap(Bundle(for: AppModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        XCTAssertEqual(String(format: es.localizedString(forKey: "connected to %@ (%lld times)", value: "∅", table: nil),
                              "maple", Int64(2)), "se conectó a maple (2 veces)")
    }
}
