import SwiftUI

// The credential proxy on this Mac (ADR 0036 §1, E3.5, E4; layer 11): a
// LaunchAgent runs `klav-proxy serve --if-registered` from the bundle's
// `klav`, and the app talks to it through its local socket, never through
// klavd. So the live list with the real connection of each sandbox, and
// «Revoke», work while Klav is locked (E2.3): the row says «Revoked on this
// Mac». Development › Sandboxes says «On this Mac» in the proxy's header,
// and Development › MCP servers whether local clients can reach it.

/// The proxy on this Mac against the account's proxy: what the panes show.
struct LocalProxyBoard: Equatable {
    let state: LocalProxyState?
    /// The account's proxy (its agent ID), if the list says.
    let accountProxy: String?
    /// The account uses Klav Cloud's proxy (ADR 0051): the one here is this
    /// Mac's own, for its local agents (Q5 (a)), not another's.
    var cloud = false

    /// It answers on its socket.
    var info: LocalProxyInfo? {
        if case .running(let info) = state { return info }
        return nil
    }

    /// The account's proxy is the one running here: «On this Mac» (E4).
    var onThisMac: Bool {
        guard let info, let accountProxy else { return false }
        return info.proxyId == accountProxy
    }

    /// A proxy runs here that isn't the account's: its socket is not
    /// asked to revoke the account's sandboxes.
    var otherProxy: Bool { info != nil && accountProxy != nil && !onThisMac && !cloud }

    /// Whether a proxy is registered here (its agent file), running or not.
    var registered: Bool {
        switch state {
        case .running: return true
        case .notRunning(let registered): return registered
        case .unavailable, nil: return false
        }
    }

    /// The live connection of `sandboxId` as the proxy on this Mac sees it,
    /// when it is the account's proxy and holds that sandbox.
    func connected(_ sandboxId: String) -> Bool? {
        guard onThisMac || accountProxy == nil, let info else { return nil }
        return info.sandboxes.first { $0.sandboxId == sandboxId }?.connected
    }

    /// Whether the proxy on this Mac can revoke `sandboxId` (it holds it).
    func holds(_ sandboxId: String) -> Bool {
        info?.sandboxes.contains { $0.sandboxId == sandboxId } ?? false
    }

    /// The URL a local client connects to for `profile`, with the port the
    /// proxy here listens on (the list only knows the default, 8790).
    func localUrl(_ url: String, profile: String) -> String {
        guard let info, info.mcpProfiles.contains(profile), info.port != 8790 else { return url }
        return url.replacingOccurrences(of: "127.0.0.1:8790/", with: "127.0.0.1:\(info.port)/")
    }
}

/// The words, apart for the tests.
enum LocalProxyWords {
    static let onThisMac = String(localized: "On this Mac")

    /// What the proxy row says, in one line.
    static func status(_ board: LocalProxyBoard, agent: AgentState) -> String {
        switch board.state {
        case .running(let info)?:
            if board.otherProxy {
                return String(localized: "Another credential proxy runs on this Mac (ID \(SandboxWords.idPrefix(info.proxyId))), not your account’s.")
            }
            if board.cloud {
                return String(localized: "Running on this Mac for its local agents, at 127.0.0.1:\(String(info.port)). Sandboxes use Klav Cloud’s proxy.")
            }
            return String(localized: "Running on this Mac, at 127.0.0.1:\(String(info.port)).")
        case .notRunning(let registered)?:
            if !registered { return String(localized: "No credential proxy is set up on this Mac.") }
            if agent == .requiresApproval {
                return String(localized: "Set up on this Mac. Allow Klav in System Settings › General › Login Items & Extensions to start it.")
            }
            return agent == .enabled
                ? String(localized: "Set up on this Mac, but it isn’t answering. Klav starts it again at login, or press Start.")
                : String(localized: "Set up on this Mac, and stopped.")
        case .unavailable(let message)?:
            return String(localized: "The proxy on this Mac can’t be asked: \(AgentText.line(message, max: 200))")
        case nil:
            return String(localized: "Checking this Mac…")
        }
    }

    /// The command that sets one up, for the terminal.
    static let setUp = "klav proxy local init --email you@example.com"

    /// «Revoked on this Mac» (E2.3), for one or all.
    static func revoked(_ info: LocalRevokeInfo) -> String {
        switch info.revoked.count {
        case 0: return String(localized: "No live sandbox on this Mac to revoke.")
        case 1:
            return info.logged
                ? String(localized: "Revoked on this Mac: it gets nothing from the proxy from now on.")
                : String(localized: "Revoked on this Mac: it gets nothing from the proxy from now on. The proxy tells the Klav server as soon as it can.")
        default:
            return info.logged
                ? String(localized: "Revoked \(Int64(info.revoked.count)) sandboxes on this Mac: they get nothing from the proxy from now on.")
                : String(localized: "Revoked \(Int64(info.revoked.count)) sandboxes on this Mac: they get nothing from the proxy from now on. The proxy tells the Klav server as soon as it can.")
        }
    }

    /// The connection, as the proxy here sees it now.
    static func connection(_ connected: Bool) -> String {
        connected ? String(localized: "Connected now, on this Mac")
                  : String(localized: "Not connected now, on this Mac")
    }

    /// The menu bar's line while locked: how many sandboxes live here.
    static func count(_ n: Int) -> String {
        n == 1 ? String(localized: "1 sandbox on this Mac")
               : String(localized: "\(Int64(n)) sandboxes on this Mac")
    }
}

extension MacModel {
    /// The proxy on this Mac, read again (a unix socket: cheap).
    func loadLocalProxy() async {
        let engine = engine
        let state = await Task.detached(priority: .userInitiated) { engine.localProxy() }.value
        localProxy = state
    }

    /// The proxy on this Mac against the account's proxy in the last list.
    var localProxyBoard: LocalProxyBoard {
        LocalProxyBoard(state: localProxy, accountProxy: sandboxList?.proxy?.agentId,
                        cloud: cloudProxy.map { $0.state != .notUsed } ?? false)
    }

    /// «Revoke» through the proxy on this Mac (E2.3): no signature and no
    /// unlocking; the proxy logs it as revoked on this Mac. `nil` is every
    /// live sandbox there.
    func revokeLocally(_ sandboxId: String?) async throws -> String {
        let info = try await run { try $0.localProxyRevoke(sandboxId: sandboxId) }
        await loadLocalProxy()
        if phase == .unlocked { await loadSandboxes(maxAge: 0) }
        return LocalProxyWords.revoked(info)
    }
}

/// The proxy on this Mac in Development › Sandboxes and › MCP servers:
/// its state and Start or Stop; how to set one up when there is none.
struct LocalProxyRow: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer

    var body: some View {
        let board = model.localProxyBoard
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("This Mac").font(.ui(12)).foregroundStyle(Palette.gris)
                Text(verbatim: LocalProxyWords.status(board, agent: installer.proxyAgent))
                    .font(.ui(12.5)).foregroundStyle(board.onThisMac ? Palette.cobalto : Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                actions(board)
            }
            if !board.registered, board.info == nil {
                Text("Set one up in the terminal, compare its 6 words, then make it your account’s proxy with klav proxy use own klav-proxy:")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                Text(verbatim: LocalProxyWords.setUp)
                    .font(.mono(12)).foregroundStyle(Palette.gris)
                    .textSelection(.enabled)
            }
            if let problem = installer.problems[.proxy] {
                Notice(text: problem)
            }
        }
    }

    @ViewBuilder
    private func actions(_ board: LocalProxyBoard) -> some View {
        let busy = installer.busy == .proxy
        if installer.proxyAgent == .enabled || board.info != nil {
            if board.info == nil {
                SmallAction(title: "Start") { Task { await start() } }.disabled(busy).fixedSize()
            }
            SmallAction(title: "Stop") { Task { await stop() } }.disabled(busy).fixedSize()
        } else if board.registered {
            SmallAction(title: "Start") { Task { await start() } }.disabled(busy).fixedSize()
        }
    }

    private func start() async {
        await installer.startLocalProxy()
        // It needs a moment to open its socket.
        for _ in 0..<10 {
            try? await Task.sleep(for: .milliseconds(300))
            await model.loadLocalProxy()
            if model.localProxyBoard.info != nil { break }
        }
    }

    private func stop() async {
        await installer.stopLocalProxy()
        try? await Task.sleep(for: .milliseconds(300))
        await model.loadLocalProxy()
    }
}

/// The menu bar while Klav is locked (E2.3): the sandboxes of the proxy on
/// this Mac, and revoking them without unlocking.
struct LocalSandboxesLine: View {
    @EnvironmentObject private var model: MacModel
    @State private var problem: String?
    @State private var done: String?

    var body: some View {
        let sandboxes = model.localProxyBoard.info?.sandboxes ?? []
        VStack(alignment: .leading, spacing: 0) {
            if !sandboxes.isEmpty || done != nil || problem != nil { Rule() }
            VStack(alignment: .leading, spacing: 6) {
            if !sandboxes.isEmpty {
                HStack(spacing: 10) {
                    IconView(icon: .cube, size: 14).foregroundStyle(Palette.tinta).frame(width: 6)
                    Text(verbatim: LocalProxyWords.count(sandboxes.count))
                        .font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
                    Spacer()
                    Menu("Revoke…") {
                        ForEach(sandboxes, id: \.sandboxId) { s in
                            Button(String(localized: "Revoke \(SandboxWords.quoted(s.label))")) {
                                Task { await revoke(s.sandboxId) }
                            }
                        }
                        if sandboxes.count > 1 {
                            Divider()
                            Button("Revoke all on this Mac") { Task { await revoke(nil) } }
                        }
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                }
                Text("Revoking here asks nothing and needs no unlocking: it only takes access away.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let done { Text(verbatim: done).font(.ui(12)).foregroundStyle(Palette.cobalto) }
            if let problem { Text(verbatim: problem).font(.ui(12)).foregroundStyle(Palette.rojo) }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, sandboxes.isEmpty && done == nil && problem == nil ? 0 : 10)
        }
        .task(id: model.generation) {
            while !Task.isCancelled {
                await model.loadLocalProxy()
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }

    private func revoke(_ id: String?) async {
        problem = nil
        do {
            done = try await model.revokeLocally(id)
        } catch {
            problem = describe(error)
        }
    }
}
