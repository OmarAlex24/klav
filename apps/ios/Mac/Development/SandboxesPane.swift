import SwiftUI

/// Development › Sandboxes (ADR 0036 E2, E4): the credential proxy on top,
/// then a security problem apart from the warnings, the theft signals in
/// red, «Active sandboxes» with «Revoke all» and «Revoke» on each row, and
/// «Ended in the last 24 h», folded. Revoking asks nothing (E2.3).
struct SandboxesPane: View {
    @EnvironmentObject private var model: MacModel
    @State private var showEnded = false

    var body: some View {
        // Ages grow while the pane is open, without reading again.
        TimelineView(.periodic(from: .now, by: 30)) { context in
            let now = Int64(context.date.timeIntervalSince1970 * 1000)
            let board = model.sandboxBoard(now: now)
            VStack(spacing: 0) {
                PaneHeader(title: "Sandboxes", detail: detail(board))
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        if let integrity = model.sandboxIntegrity {
                            SecurityBlock(text: integrity.text, detail: integrity.detail, command: integrity.command) {
                                SmallAction(title: "Read again") { Task { await model.loadSandboxes(maxAge: 0) } }
                                    .fixedSize()
                            }
                            .padding(.bottom, 16)
                        }
                        // In every state of the pane: without a list, after
                        // a failed read, while the first one runs (E3.3).
                        ForEach(model.unregisteredRevocations) { check in
                            UnregisteredRevocationBlock(check: check).padding(.bottom, 16)
                        }
                        if let board {
                            content(board)
                        } else if let problem = model.sandboxProblem {
                            Notice(text: problem)
                        }
                        // Without a list, what the last action answered
                        // (a failed «Revoke again») still shows.
                        if board == nil, let notice = model.shownSandboxNotice {
                            Notice(text: notice.text, tone: notice.error ? .error : .info).padding(.top, 12)
                        }
                        if board == nil, model.sandboxProblem == nil, model.sandboxIntegrity == nil {
                            ProgressView().controlSize(.small).padding(.top, 40).frame(maxWidth: .infinity)
                        }
                    }
                    .frame(maxWidth: 660, alignment: .leading)
                    .padding(.horizontal, 28)
                    .padding(.vertical, 24)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        // While the pane is open it reads again every minute, so the proxy's
        // quiet is judged again by `klav-client`; each read syncs and
        // verifies the log, so not more often.
        .task(id: model.generation) {
            while !Task.isCancelled {
                await model.loadSandboxes(maxAge: 30)
                try? await Task.sleep(for: .seconds(60))
            }
        }
        .sheet(isPresented: $model.revokingAllSandboxes, onDismiss: { model.revokeAllFor = nil }) {
            RevokeAllSandboxesSheet()
                .environmentObject(model)
                .frame(width: 520, height: 520)
        }
    }

    private func detail(_ board: SandboxBoard?) -> String? {
        guard let board, !board.noProxy || !board.live.isEmpty else { return nil }
        return String(localized: "\(Int64(board.live.count)) live")
    }

    @ViewBuilder
    private func content(_ board: SandboxBoard) -> some View {
        if let security = board.security {
            SecurityBlock(text: SandboxWords.security(security, everyProxy: board.everyProxysRows),
                          command: { if case .preferencesByAgent = security { true } else { false } }())
                .padding(.bottom, 16)
        }
        if board.paused {
            PausedLine().padding(.bottom, 16)
        }
        ProxyBlock(board: board)
        ForEach(board.warnings, id: \.self) { warning in
            Notice(text: AgentText.line(warning, max: 300), tone: .info).padding(.top, 12)
        }
        if let problem = model.sandboxProblem { Notice(text: problem).padding(.top, 12) }
        if let notice = model.shownSandboxNotice {
            Notice(text: notice.text, tone: notice.error ? .error : .info).padding(.top, 12)
        }

        if board.showsList {
            if !board.thefts.isEmpty {
                SectionLabel("Theft signals").padding(.top, 28).padding(.bottom, 10)
                VStack(spacing: 10) {
                    ForEach(board.thefts, id: \.sandboxId) { theft in TheftBlock(sandbox: theft, board: board) }
                }
            }
            activeHeader(board).padding(.top, 28).padding(.bottom, 10)
            if board.live.isEmpty {
                Text("No sandbox is live. An issuer starts one with klav sandbox start.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                rows(board.live, board: board)
            }
            if !board.ended.isEmpty { ended(board) }
            source(board).padding(.top, 24)
        }
    }

    private func activeHeader(_ board: SandboxBoard) -> some View {
        HStack(spacing: 10) {
            if board.everyProxysRows {
                SectionLabel("Active sandboxes (all proxies)")
            } else {
                SectionLabel("Active sandboxes")
            }
            if !board.revokeAll.isEmpty {
                SmallAction(title: "Revoke all…") {
                    model.revokeAllFor = nil
                    model.revokingAllSandboxes = true
                }
                    .fixedSize()
            }
        }
    }

    private func rows(_ list: [SandboxInfo], board: SandboxBoard) -> some View {
        FieldBlock {
            ForEach(Array(list.enumerated()), id: \.element.sandboxId) { index, sandbox in
                if index > 0 { Rule() }
                SandboxRow(sandbox: sandbox, board: board)
            }
        }
    }

    @ViewBuilder
    private func ended(_ board: SandboxBoard) -> some View {
        Button { showEnded.toggle() } label: {
            HStack(spacing: 8) {
                IconView(icon: .back, size: 12)
                    .rotationEffect(.degrees(showEnded ? -90 : 180))
                    .foregroundStyle(Palette.gris)
                SectionLabel("Ended in the last 24 h (\(Int64(board.ended.count)))")
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityValue(showEnded ? Text("Shown") : Text("Hidden"))
        .padding(.top, 28)
        .padding(.bottom, 10)
        if showEnded { rows(board.ended, board: board) }
    }

    /// Where the list comes from, and «Read again» (each read syncs and
    /// verifies the log).
    private func source(_ board: SandboxBoard) -> some View {
        HStack(spacing: 10) {
            Text(verbatim: String(localized: "From the verified log, up to event #\(Int64(board.list.verifiedEvents)).")
                 + " " + SandboxWords.read(board.readMs, now: board.now))
                .font(.ui(12)).foregroundStyle(Palette.gris)
            Spacer(minLength: 8)
            SmallAction(title: "Read again") {
                Task { await model.loadSandboxes(maxAge: 0) }
            }
            .disabled(model.readingSandboxes)
        }
    }
}

// MARK: - The proxy

/// The header (ADR 0036 §13, E4): the account's proxy with its short ID,
/// paused or not, the age of its heartbeat or why there are no signs. A
/// heartbeat that went back is a security warning, in red. Without a
/// proxy: what is lost and how to set one, in the terminal.
private struct ProxyBlock: View {
    let board: SandboxBoard

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            IconView(icon: .cube, size: 16)
                .foregroundStyle(Palette.tinta)
                .frame(width: 28, height: 28)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            VStack(alignment: .leading, spacing: 6) {
                if let proxy = board.proxy { withProxy(proxy) } else { withoutProxy }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .overlay(Rectangle().strokeBorder(rollback ? Palette.rojo : Palette.linea, lineWidth: 1))
        .crossCorners()
    }

    private var rollback: Bool { board.proxy?.noSigns == .rollback }

    @ViewBuilder
    private func withProxy(_ proxy: SandboxProxyInfo) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("Credential proxy").font(.ui(12)).foregroundStyle(Palette.gris)
            Spacer(minLength: 8)
            if board.paused {
                Text("Paused")
                    .font(.ui(11, .medium)).foregroundStyle(Palette.cobalto)
                    .padding(.horizontal, 6).frame(height: 20)
                    .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
            }
        }
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(verbatim: SandboxWords.proxyName(proxy))
                .font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
            Text(verbatim: "ID \(SandboxWords.idPrefix(proxy.agentId))")
                .font(.mono(11)).foregroundStyle(Palette.gris)
                .textSelection(.enabled)
        }
        let (text, tone) = SandboxWords.heartbeat(proxy, paused: board.paused, now: board.now, readMs: board.readMs,
                                                  stale: board.stale)
        if tone == .alert {
            HStack(alignment: .top, spacing: 8) {
                Rectangle().fill(Palette.rojo).frame(width: 7, height: 7).padding(.top, 5)
                Text(verbatim: text)
                    .font(.ui(13, .medium)).foregroundStyle(Palette.rojo)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
        } else {
            Text(verbatim: text)
                .font(.ui(12.5)).foregroundStyle(tone == .agent ? Palette.cobalto : Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
        }
        // Without live sandboxes the proxy beats every 30 minutes (E3.3).
        if board.live.isEmpty, tone != .alert, !board.paused, !board.stale {
            Text("Without live sandboxes it checks in every 30 minutes.")
                .font(.ui(12)).foregroundStyle(Palette.gris)
        }
    }

    @ViewBuilder
    private var withoutProxy: some View {
        Group {
            if board.security == nil { Text("No proxy") } else { Text("No proxy trusted") }
        }
        .font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
        if board.security == nil {
            Text("Without a credential proxy there are no sandboxes with their own credentials, no presets that keep a token out of a sandbox, no approval and log entry for each call, no MCP gate and no theft signal.")
                .font(.ui(12.5)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Text("Set one up in the terminal: run klav-proxy init where it will live, then klav proxy use own with its name.")
                .font(.ui(12.5)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text(verbatim: SandboxWords.chooseProxy)
                .font(.mono(12)).foregroundStyle(Palette.gris)
                .textSelection(.enabled)
        }
    }
}

/// A security problem, above everything, in red: the list's flag, or a
/// read that failed its checks. With the flag, or a proxy setting the
/// server doesn't list, the terminal's command (the app can't set the
/// proxy). A check this build has no words for shows `klav-client`'s own,
/// apart, under their label.
private struct SecurityBlock<Actions: View>: View {
    let text: String
    var detail: String?
    var command = false
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Rectangle().fill(Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Security problem").font(.ui(15, .semibold)).foregroundStyle(Palette.rojo)
                Text(verbatim: text)
                    .font(.ui(13)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    Text("What the check said (in English):")
                        .font(.ui(12.5)).foregroundStyle(Palette.gris)
                        .padding(.top, 2)
                    Text(verbatim: detail)
                        .font(.mono(12)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                if command {
                    Text("The terminal changes it, with Touch ID:")
                        .font(.ui(12.5)).foregroundStyle(Palette.gris)
                        .padding(.top, 2)
                    Text(verbatim: SandboxWords.chooseProxy)
                        .font(.mono(12)).foregroundStyle(Palette.tinta)
                        .textSelection(.enabled)
                }
                actions().padding(.top, 4)
            }
            .padding(14)
            Spacer(minLength: 0)
        }
        .background(Palette.niebla)
        .overlay(Rectangle().strokeBorder(Palette.rojo, lineWidth: 1))
        .crossCorners()
    }
}

extension SecurityBlock where Actions == EmptyView {
    init(text: String, command: Bool = false) {
        self.init(text: text, detail: nil, command: command) { EmptyView() }
    }
}

/// «The server didn’t register your revocation» (ADR 0036 E3.3): a read
/// after the server's answer doesn't show it in the verified log. Klav
/// checks again on every read; the person can revoke again, pause agents
/// or open the proxy's page to revoke it.
private struct UnregisteredRevocationBlock: View {
    @EnvironmentObject private var model: MacModel
    let check: RevocationCheck
    @State private var busy = false

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Rectangle().fill(Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("The server didn’t register your revocation")
                    .font(.ui(15, .semibold)).foregroundStyle(Palette.rojo)
                Text(verbatim: SandboxWords.unregistered(check))
                    .font(.ui(13)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    SmallAction(title: busy ? "Revoking…" : "Revoke again") { Task { await again() } }
                        .disabled(busy)
                    SmallAction(title: "Pause agents…") { model.section = .agents }
                    SmallAction(title: "Open the proxy") {
                        model.openAgent = check.proxyId
                        model.section = .agents
                    }
                }
                .padding(.top, 4)
            }
            .padding(14)
            Spacer(minLength: 0)
        }
        .overlay(Rectangle().strokeBorder(Palette.rojo, lineWidth: 1))
        .crossCorners()
        .accessibilityElement(children: .contain)
    }

    private func again() async {
        busy = true
        do { _ = try await model.revokeAgain(check) } catch { model.say(SandboxWords.failure(error), error: true) }
        busy = false
    }
}

/// «Agents are paused: no sandbox can use the proxy» (E4), with the mark
/// of the pause.
private struct PausedLine: View {
    var body: some View {
        HStack(spacing: 10) {
            CompactMark().frame(width: 6, height: 22)
            Text("Agents are paused: no sandbox can use the proxy.")
                .font(.ui(13, .medium)).foregroundStyle(Palette.cobalto)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
    }
}

// MARK: - Rows

/// The label in quotes, marked as the issuer's (T136), with the start of
/// the sandbox's ID.
private struct SandboxLabel: View {
    let sandbox: SandboxInfo
    var color: Color = Palette.tinta

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(verbatim: SandboxWords.quoted(sandbox.label))
                .font(.ui(14, .medium)).foregroundStyle(color)
                .lineLimit(1)
            Text("according to the issuer").font(.ui(12)).foregroundStyle(Palette.gris)
            Text(verbatim: SandboxWords.idPrefix(sandbox.sandboxId))
                .font(.mono(11)).foregroundStyle(Palette.gris)
        }
    }
}

/// The issuer, which opens its page in Agents.
private struct IssuerLink: View {
    @EnvironmentObject private var model: MacModel
    let sandbox: SandboxInfo

    var body: some View {
        Button {
            model.openAgent = sandbox.issuerId
            model.section = .agents
        } label: {
            Text(verbatim: SandboxWords.issuer(sandbox))
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .underline(true, color: Palette.linea)
        }
        .buttonStyle(.plain)
        .accessibilityHint(Text("Opens the issuer’s page"))
    }
}

private struct SandboxRow: View {
    @EnvironmentObject private var model: MacModel
    let sandbox: SandboxInfo
    let board: SandboxBoard
    @State private var busy = false

    var body: some View {
        let (state, note, tone) = SandboxWords.state(sandbox, paused: board.paused, now: board.now)
        let live = SandboxBoard.isLive(sandbox)
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    SandboxLabel(sandbox: sandbox)
                    Text(verbatim: SandboxWords.profiles(sandbox))
                        .font(.ui(12.5)).foregroundStyle(Palette.tinta)
                    HStack(spacing: 6) {
                        IssuerLink(sandbox: sandbox)
                        if live {
                            Text(verbatim: "·").font(.ui(12)).foregroundStyle(Palette.gris)
                            Text(verbatim: SandboxWords.expiry(sandbox, now: board.now))
                                .font(.ui(12)).foregroundStyle(Palette.gris)
                        }
                    }
                    if let connection = SandboxWords.connection(sandbox, proxy: board.proxy, paused: board.paused,
                                                                 now: board.now, readMs: board.readMs,
                                                                 stale: board.stale) {
                        Text(verbatim: connection).font(.ui(12)).foregroundStyle(Palette.gris)
                    }
                }
                Spacer(minLength: 12)
                VStack(alignment: .trailing, spacing: 8) {
                    if live && board.paused {
                        Text("Paused")
                            .font(.ui(11, .medium)).foregroundStyle(Palette.cobalto)
                            .padding(.horizontal, 6).frame(height: 20)
                            .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
                    }
                    Text(verbatim: state)
                        .font(.ui(12, .medium))
                        .foregroundStyle(tone == .agent ? Palette.cobalto : tone == .alert ? Palette.rojo : Palette.gris)
                    if SandboxBoard.revocable(sandbox) {
                        SmallAction(title: busy ? "Revoking…" : "Revoke",
                                    label: String(localized: "Revoke \(SandboxWords.quoted(sandbox.label))")) {
                            Task { await revoke() }
                        }
                        .disabled(busy)
                    }
                }
                .fixedSize()
            }
            if let note {
                Text(verbatim: note).font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }

    private func revoke() async {
        busy = true
        do {
            _ = try await model.revokeSandbox(sandbox)
        } catch {
            model.say(SandboxWords.failure(error), error: true)
        }
        busy = false
    }
}

/// A theft signal (E2.1), in red until «Got it»: never hidden.
private struct TheftBlock: View {
    @EnvironmentObject private var model: MacModel
    let sandbox: SandboxInfo
    let board: SandboxBoard
    @State private var problem: String?
    @State private var pausing = false

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Rectangle().fill(Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Theft signal").font(.ui(12, .medium)).foregroundStyle(Palette.rojo)
                SandboxLabel(sandbox: sandbox)
                HStack(spacing: 6) {
                    IssuerLink(sandbox: sandbox)
                    if let ended = sandbox.endedMs {
                        Text(verbatim: "·").font(.ui(12)).foregroundStyle(Palette.gris)
                        Text(verbatim: String(localized: "Ended \(SandboxWords.ago(board.now - ended))"))
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                    }
                }
                Text(verbatim: SandboxWords.theft)
                    .font(.ui(13)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
                HStack(spacing: 6) {
                    SmallAction(title: "See activity") { model.openActivity(agent: sandbox.proxyId) }
                    SmallAction(title: pausing ? "Pausing…" : "Pause the issuer") { Task { await pauseIssuer() } }
                        .disabled(pausing)
                    Spacer(minLength: 6)
                    SmallAction(title: "Got it") {
                        model.sandboxNotice = nil
                        model.gotIt(theft: sandbox.sandboxId)
                    }
                }
                .padding(.top, 4)
                if let problem { Notice(text: problem) }
            }
            .padding(14)
            Spacer(minLength: 0)
        }
        .overlay(Rectangle().strokeBorder(Palette.rojo, lineWidth: 1))
        .crossCorners()
    }

    /// Pausing the issuer cuts its other sandboxes too (E2.2), asking nothing.
    private func pauseIssuer() async {
        pausing = true
        problem = nil
        model.sandboxNotice = nil
        do { try await model.pauseAgents(agentId: sandbox.issuerId, minutes: nil) } catch { problem = describe(error) }
        pausing = false
    }
}

// MARK: - «Revoke all»

/// One confirmation in a sheet, without Touch ID (E2.2): how many, that it
/// cuts the work of those conversations, and that issuers can start others,
/// with «Pause agents» and each issuer's page to stop that.
private struct RevokeAllSandboxesSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var problem: String?

    /// The proxy it signs for, and how many if the list can say: from
    /// «Revoke again» it may be another proxy, or there may be no list.
    private var scope: RevokeAllScope? { model.revokeAllScope }
    private var covered: [SandboxInfo] { scope?.covered ?? [] }

    /// Each issuer once, in the list's order.
    private var issuers: [SandboxInfo] {
        var seen = Set<String>()
        return covered.filter { seen.insert($0.issuerId).inserted }
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let scope, scope.covered == nil {
                        unknownCount(scope)
                    } else {
                        knownCount
                    }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            footer
        }
        .background(Palette.papel)
    }

    /// The list on screen is that proxy's: how many, and each issuer.
    @ViewBuilder
    private var knownCount: some View {
        Title(covered.count == 1 ? String(localized: "Revoke 1 sandbox?")
                                 : String(localized: "Revoke \(Int64(covered.count)) sandboxes?"),
              size: 22)
        Text("Every sandbox of your proxy issued so far gets no access from its next call: the conversations working in them stop. Nothing asks for Touch ID, and there is no undo.")
            .font(.ui(13)).foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 10)
        Text("Their issuers can start others. To stop that, pause agents, or pause, remove or revoke each issuer:")
            .font(.ui(13)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 14)
        FieldBlock {
            ForEach(Array(issuers.enumerated()), id: \.element.issuerId) { index, sandbox in
                if index > 0 { Rule() }
                HStack {
                    Text(verbatim: SandboxWords.issuer(sandbox))
                        .font(.ui(13)).foregroundStyle(Palette.tinta)
                    Spacer()
                    SmallAction(title: "Open") {
                        model.openAgent = sandbox.issuerId
                        model.section = .agents
                        dismiss()
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
            }
        }
        .padding(.top, 10)
    }

    /// No list, or not that proxy's: it can't say how many, and still
    /// revokes them all.
    @ViewBuilder
    private func unknownCount(_ scope: RevokeAllScope) -> some View {
        Title(String(localized: "Revoke every sandbox of this proxy?"), size: 22)
        Text(verbatim: String(localized: "Klav can’t tell right now how many sandboxes this covers. Every sandbox the proxy with ID \(SandboxWords.idPrefix(scope.proxyId)) has issued so far gets no access from its next call, and the conversations working in them stop. Their issuers can start others; to stop that, pause agents. Nothing asks for Touch ID, and there is no undo."))
            .font(.ui(13)).foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 10)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Button("Pause agents…") {
                model.section = .agents
                dismiss()
            }
            .buttonStyle(SecondaryButtonStyle(compact: true))
            .fixedSize()
            Spacer()
            Button("Cancel") { dismiss() }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .keyboardShortcut(.cancelAction)
                .fixedSize()
            Button(busy ? String(localized: "Revoking…") : String(localized: "Revoke all")) {
                Task { await revoke() }
            }
            .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
            .disabled(busy || scope == nil || scope?.covered?.isEmpty == true)
            .fixedSize()
        }
        .padding(.horizontal, 20)
        .frame(height: 64)
        .overlay(alignment: .top) { Rule() }
    }

    private func revoke() async {
        guard scope != nil else { return }
        busy = true
        problem = nil
        do {
            _ = try await model.confirmRevokeAll()
            dismiss()
        } catch {
            problem = SandboxWords.failure(error)
        }
        busy = false
    }
}

// MARK: - The menu bar

/// The theft signals in the menu bar's panel (ADR 0036 E4), in red beside
/// the other red notices, whatever else the panel shows. «See» opens
/// Development › Sandboxes.
struct SandboxTheftsView: View {
    @EnvironmentObject private var model: MacModel
    var open: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // A read that failed its checks drops the list, theft signals
            // included: say so here, in red, instead of going quiet.
            if model.sandboxIntegrity != nil {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("The sandbox list failed its security checks")
                        .font(.ui(12.5, .medium)).foregroundStyle(Palette.rojo)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                    SmallAction(title: "See") {
                        model.openSandboxes()
                        open?()
                    }
                }
            }
            ForEach(model.shownThefts, id: \.sandboxId) { theft in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(verbatim: String(localized: "Theft signal in \(SandboxWords.quoted(theft.label)) (according to the issuer)"))
                        .font(.ui(12.5, .medium)).foregroundStyle(Palette.rojo)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                    SmallAction(title: "See", label: String(localized: "See the theft signal in \(SandboxWords.quoted(theft.label))")) {
                        model.openSandboxes()
                        open?()
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
