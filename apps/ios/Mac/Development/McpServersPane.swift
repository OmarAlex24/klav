import SwiftUI

/// Development › MCP servers (ADR 0049 §3, §9): the MCP profiles the
/// account's proxy holds, each with its endpoint, the URL a client on this
/// Mac connects to, its tool rules in three lanes (allowed, asks you,
/// denied) and the local clients that may use it. Above them, the
/// account's gateway switch, which a one-time sheet turns on after «update
/// every device first» when the account has another device or its own
/// proxy, and Touch ID alone turns on when this Mac is all there is (ADR
/// 0049, amendment of 2026-11-27). Names, hosts and patterns only: never a
/// key or a client's token.
struct McpServersPane: View {
    @EnvironmentObject private var model: MacModel
    @State private var info: McpServersInfo?
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "MCP servers", detail: info.flatMap { McpServersWords.headerDetail($0) })
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let info {
                        content(info)
                    } else if let problem {
                        Notice(text: problem)
                    } else {
                        ProgressView().controlSize(.small).padding(.top, 40).frame(maxWidth: .infinity)
                    }
                }
                .frame(maxWidth: 660, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: model.generation) { await load() }
        .task(id: model.generation) { await model.loadLocalProxy() }
        .sheet(isPresented: $model.turningOnMcpGateway) {
            TurnOnGatewaySheet { await load() }
                .environmentObject(model)
                .frame(width: 500, height: 370)
        }
    }

    private func load() async {
        do {
            info = try await model.run { try $0.mcpServers() }
            problem = nil
        } catch {
            problem = describe(error)
        }
    }

    /// Nothing on the account is older than the gateway: Touch ID (or the
    /// master password) alone. `klavd` checks that again and refuses
    /// without «update every device first» if it changed meanwhile.
    private func turnOnAlone() async {
        do {
            try await model.withPresenceResult(String(localized: "Turn on the MCP gateway for your account")) { engine, password in
                try engine.turnMcpGatewayOnWithPassword(everyDeviceUpdated: false, password: password)
            } done: { _ in
                model.show(Toast(text: String(localized: "The MCP gateway is on.")))
                Task { await load() }
            }
        } catch {
            await load()
            problem = describe(error)
        }
    }

    @ViewBuilder
    private func content(_ info: McpServersInfo) -> some View {
        // Local clients reach these servers only through the proxy on this
        // Mac (ADR 0049 §3.1): whether it runs, and Start or Stop.
        CloudProxyRow(edge: .bottom)
        if info.proxy != nil {
            LocalProxyRow().padding(.bottom, 20)
        }
        switch info.gatewayOn {
        case nil:
            Notice(text: String(localized: "This Klav server is older than the MCP gateway. Update the server to use MCP servers through your proxy."))
                .padding(.bottom, 20)
        case false?:
            GatewayOff(alone: !info.needsUpdateWarning) {
                if info.needsUpdateWarning {
                    model.turningOnMcpGateway = true
                } else {
                    Task { await turnOnAlone() }
                }
            }
            .padding(.bottom, 24)
        case true?:
            EmptyView()
        }
        ForEach(info.problems, id: \.self) { line in
            Notice(text: AgentText.line(line, max: 300)).padding(.bottom, 12)
        }
        if let problem { Notice(text: problem).padding(.bottom, 12) }
        if info.servers.isEmpty {
            empty(info)
        } else {
            VStack(alignment: .leading, spacing: 22) {
                ForEach(info.servers, id: \.profile) { server in
                    ServerBlock(server: server)
                }
            }
            Text("Your proxy forwards only the tools these rules allow, asks you for the ones marked so, and hides the rest from each client’s tool list. To change the rules, run klav proxy grant again; to add a client, klav client connect.")
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 22)
        }
    }

    private func empty(_ info: McpServersInfo) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No MCP servers yet")
                .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
            Text(info.proxy == nil
                 ? String(localized: "MCP servers go through your own credential proxy, and this account has none yet. Set one up with klav proxy use own, then add a server:")
                 : String(localized: "Add a remote MCP server that takes an API key, with the tools it may call:"))
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            CommandLine(text: "klav proxy grant ITEM --profile NAME --mcp-url https://HOST/mcp --tools-allow 'get_*' --tools-ask 'delete_*'")
        }
    }
}

/// The words of the pane, apart for the tests.
enum McpServersWords {
    static func headerDetail(_ info: McpServersInfo) -> String? {
        switch info.gatewayOn {
        case true?:
            return info.servers.count == 1 ? String(localized: "1 server")
                                           : String(localized: "\(Int64(info.servers.count)) servers")
        case false?: return String(localized: "Gateway off")
        case nil: return nil
        }
    }

    /// «Claude Code» for a known client, its own name otherwise.
    static func client(_ name: String) -> String {
        ActivityWords.knownClientNames[name] ?? AgentText.line(name, max: 32)
    }

    static func clients(_ server: McpServerInfo) -> String? {
        guard !server.clients.isEmpty else { return nil }
        return ListFormatter.localizedString(byJoining: server.clients.map(client))
    }
}

/// The switch is off: what turning it on does, and the button. `alone`:
/// nothing on the account is older than the gateway, so the button asks
/// for Touch ID instead of opening the sheet.
private struct GatewayOff: View {
    let alone: Bool
    let turnOn: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 18) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 40, height: 96)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("The MCP gateway is off for this account")
                    .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                Text("Turning it on lets your proxy say which tool each call uses, so your rules can allow, ask about or deny each tool, and Activity shows who called it. It stays on.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                if alone {
                    Text("Nothing on your account is older than the gateway: this Mac is its only device, and it has no klav-proxy of its own.")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button(alone ? String(localized: "Turn on") : String(localized: "Turn on…"), action: turnOn)
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .fixedSize()
                    .padding(.top, 6)
            }
        }
    }
}

/// One MCP server: its name and where it lives, the URL for a client on
/// this Mac, its rules in lanes, and who may use it.
private struct ServerBlock: View {
    @EnvironmentObject private var model: MacModel
    let server: McpServerInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(verbatim: server.profile)
                    .font(.mono(15)).foregroundStyle(Palette.tinta)
                if !server.title.isEmpty, server.title != server.profile {
                    Text(verbatim: AgentText.line(server.title, max: 60))
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .lineLimit(1)
                }
                Spacer()
                Text(verbatim: AgentText.line(server.upstream + server.endpoint, max: 80))
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .lineLimit(1).truncationMode(.middle)
            }
            .padding(.bottom, 10)
            FieldBlock {
                urlRow
                Rule()
                lane(String(localized: "mcp.lane.allowed"), server.toolsAllow, color: Palette.tinta)
                Rule()
                lane(String(localized: "mcp.lane.ask"), server.toolsAsk, color: Palette.cobalto)
                Rule()
                lane(String(localized: "mcp.lane.denied"), server.toolsDeny, color: Palette.rojo)
                Rule()
                Text("Every other tool is denied and hidden from the list.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.vertical, 9)
                Rule()
                clientsRow
            }
        }
        .accessibilityElement(children: .contain)
    }

    private var urlRow: some View {
        HStack(spacing: 10) {
            Text("On this Mac")
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .frame(width: 92, alignment: .leading)
            Text(verbatim: model.localProxyBoard.localUrl(server.localUrl, profile: server.profile))
                .font(.mono(12.5)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 8)
            SmallAction(title: "Copy", label: String(localized: "Copy the URL of \(server.profile)")) {
                Clipboard.copy(model.localProxyBoard.localUrl(server.localUrl, profile: server.profile))
            }
            .fixedSize()
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
    }

    /// One effect's patterns, in the grant's order, as signed.
    private func lane(_ name: String, _ patterns: [String], color: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(verbatim: name)
                .font(.ui(12, .medium)).foregroundStyle(color)
                .frame(width: 92, alignment: .leading)
            if patterns.isEmpty {
                Text("mcp.lane.none").font(.ui(12.5)).foregroundStyle(Palette.gris)
            } else {
                Flow(spacing: 12) {
                    ForEach(patterns, id: \.self) { pattern in
                        Text(verbatim: pattern)
                            .font(.mono(12.5)).foregroundStyle(Palette.tinta)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var clientsRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("Clients")
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .frame(width: 92, alignment: .leading)
            if let clients = McpServersWords.clients(server) {
                Text(verbatim: clients).font(.ui(12.5)).foregroundStyle(Palette.tinta)
            } else {
                Text(verbatim: String(localized: "None yet. Connect one with klav client connect claude-code --mcp \(server.profile)"))
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
    }
}

/// A command to copy, as the terminal shows it.
private struct CommandLine: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(verbatim: text)
                .font(.mono(12)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            SmallAction(title: "Copy") { Clipboard.copy(text) }.fixedSize()
        }
        .padding(12)
        .background(Palette.niebla)
    }
}

/// «Turn on the MCP gateway?»: what older devices lose, the person's word
/// that every device is updated, then Touch ID (or the master password).
struct TurnOnGatewaySheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let done: () async -> Void
    @State private var updated = false
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Title(String(localized: "Turn on the MCP gateway?"), size: 22)
                    Text("Once it’s on, approvals and Activity name the MCP tool of each call. Klav apps, CLIs and klav-proxy older than the gateway can’t read that: their requests list fails and log verification reports tampering, and an older proxy stops serving until it’s updated.")
                        .font(.ui(13)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 10)
                    Text("Devices don’t report their Klav version, so Klav can’t check this for you. The gateway can’t be turned off.")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 10)
                    CheckRow(state: updated ? .on : .off,
                             label: String(localized: "Klav is updated on every device, and klav-proxy too"),
                             action: { updated.toggle() }) {
                        Text("Klav is updated on every device, and klav-proxy too")
                            .font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.top, 18)
                    if let problem { Notice(text: problem).padding(.top, 14) }
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 10) {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .keyboardShortcut(.cancelAction)
                    .fixedSize()
                Button(busy ? model.waitingForPresence : String(localized: "Turn on")) {
                    Task { await turnOn() }
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .disabled(busy || !updated)
                .fixedSize()
            }
            .padding(.horizontal, 20)
            .frame(height: 64)
            .overlay(alignment: .top) { Rule() }
        }
        .background(Palette.papel)
        // On a Mac without Touch ID, the master password over this sheet:
        // macOS shows no second sheet from the window under it.
        .sheet(item: model.passwordPromptHere(.mcpGatewaySheet)) { prompt in
            PasswordSheet(prompt: prompt).environmentObject(model)
        }
        .onDisappear { model.withdrawPrompt(over: .mcpGatewaySheet) }
    }

    private func turnOn() async {
        busy = true
        problem = nil
        do {
            try await model.withPresenceResult(String(localized: "Turn on the MCP gateway for your account"),
                                               host: .mcpGatewaySheet) { engine, password in
                try engine.turnMcpGatewayOnWithPassword(everyDeviceUpdated: true, password: password)
            } done: { _ in
                model.show(Toast(text: String(localized: "The MCP gateway is on.")))
                dismiss()
                Task { await done() }
            }
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}
