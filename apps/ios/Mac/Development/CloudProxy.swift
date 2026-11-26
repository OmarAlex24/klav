import SwiftUI

// Klav Cloud's proxy (ADR 0051 §6.1, §6.3, §4.4) in Development ›
// Sandboxes and › MCP servers: the row when the account uses it (attested,
// its version and commit, the PCRs on «Details»), the red row when it
// couldn't be verified (with «Stop using it», and «Set it up again» when it
// lost its keys), and «Use Klav Cloud Proxy» for an entitled account. Every
// check runs in `klav-client` through klavd; this only shows the answer.
//
// The proxy on this Mac (Q5 (a)) stays as it is: its row and its Start and
// Stop come right after, and it keeps serving this Mac's local agents.

extension MacModel {
    /// Reads Klav Cloud's proxy again: klavd checks the manifest and a
    /// fresh attestation, so it takes a moment.
    func loadCloudProxy() async {
        guard phase == .unlocked else { return }
        do {
            cloudProxy = try await run { try $0.hostedProxy() }
            cloudProxyProblem = nil
        } catch {
            cloudProxyProblem = describe(error)
        }
    }

    /// «Use Klav Cloud Proxy», «Stop using it» or «Set it up again»:
    /// Touch ID in klavd, or the master password here.
    func actOnCloudProxy(_ action: HostedProxyAction) async {
        cloudProxyBusy = true
        defer { cloudProxyBusy = false }
        do {
            try await withPresenceResult(CloudProxyWords.reasonFor(action)) { engine, password in
                try engine.hostedProxyActWithPassword(action: action, password: password)
            } done: { [weak self] outcome in
                guard let self else { return }
                self.cloudProxy = outcome.info
                self.cloudProxyNotes = CloudProxyWords.notes(outcome)
                self.cloudProxyProblem = nil
                Task { await self.loadSandboxes(maxAge: 0) }
            }
        } catch is CancellationError {
        } catch {
            cloudProxyProblem = describe(error)
        }
    }
}

/// The row, in Development › Sandboxes and › MCP servers.
struct CloudProxyRow: View {
    @EnvironmentObject private var model: MacModel
    @State private var details = false
    /// Where the gap to its neighbour goes, only when it shows something.
    var edge: Edge.Set = .top

    var body: some View {
        // A stack, not a `Group`: an empty `Group` has no view to run
        // `.task` on, so the row would never load. With nothing to show it
        // has no size, and the parents use no spacing.
        VStack(alignment: .leading, spacing: 0) {
            if let info = model.cloudProxy {
                content(info).padding(edge, 12)
            } else if let problem = model.cloudProxyProblem {
                Notice(text: problem).padding(edge, 12)
            }
        }
        .task(id: model.generation) { await model.loadCloudProxy() }
    }

    @ViewBuilder
    private func content(_ info: HostedProxyInfo) -> some View {
        if info.needsAttention {
            red(info)
        } else if let line = CloudProxyWords.headline(info) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("Klav Cloud").font(.ui(12)).foregroundStyle(Palette.gris)
                    Text(verbatim: line)
                        .font(.ui(12.5))
                        .foregroundStyle(info.state == .verified ? Palette.cobalto : Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    actions(info)
                }
                if info.state == .notUsed {
                    Text(verbatim: CloudProxyWords.useNote(replacesOwn: info.replacesOwn))
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if details, info.state == .verified { detailLines(info) }
                footer
            }
        }
    }

    @ViewBuilder
    private func actions(_ info: HostedProxyInfo) -> some View {
        switch info.state {
        case .verified:
            SmallAction(title: details ? "Hide details" : "Details") { details.toggle() }.fixedSize()
            SmallAction(title: "Stop using it") { Task { await model.actOnCloudProxy(.stop) } }
                .disabled(model.cloudProxyBusy).fixedSize()
        case .notUsed:
            SmallAction(title: "Use Klav Cloud Proxy") { Task { await model.actOnCloudProxy(.use) } }
                .disabled(model.cloudProxyBusy).fixedSize()
        case .unreachable:
            SmallAction(title: "Check again") { Task { await model.loadCloudProxy() } }.fixedSize()
        default:
            EmptyView()
        }
    }

    private func red(_ info: HostedProxyInfo) -> some View {
        HStack(alignment: .top, spacing: 0) {
            Rectangle().fill(Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Klav Cloud’s proxy").font(.ui(15, .semibold)).foregroundStyle(Palette.rojo)
                if let line = CloudProxyWords.headline(info) {
                    Text(verbatim: line).font(.ui(13)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let reason = CloudProxyWords.reason(info) {
                    Text(verbatim: reason).font(.ui(12.5)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(verbatim: CloudProxyWords.keeps).font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    SmallAction(title: "Stop using it") { Task { await model.actOnCloudProxy(.stop) } }
                        .disabled(model.cloudProxyBusy).fixedSize()
                    if info.state == .lostKeys || info.state == .revoked {
                        SmallAction(title: "Set it up again") { Task { await model.actOnCloudProxy(.reset) } }
                            .disabled(model.cloudProxyBusy).fixedSize()
                    }
                }
                .padding(.top, 4)
                footer
            }
            .padding(14)
            Spacer(minLength: 0)
        }
        .background(Palette.niebla)
        .overlay(Rectangle().strokeBorder(Palette.rojo, lineWidth: 1))
        .crossCorners()
    }

    private func detailLines(_ info: HostedProxyInfo) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            if let commit = info.commit { line("Commit", commit) }
            if let seq = info.manifestSeq { line("Manifest", "deploy/nitro/manifests/\(seq).json") }
            if let pcr0 = info.pcr0 { line("PCR0", pcr0) }
            if let pcr1 = info.pcr1 { line("PCR1", pcr1) }
            if let pcr2 = info.pcr2 { line("PCR2", pcr2) }
            if let channel = info.channel { line("Channel", channel) }
        }
        .padding(.leading, 2)
    }

    private func line(_ label: LocalizedStringKey, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label).font(.ui(11.5)).foregroundStyle(Palette.gris).frame(width: 64, alignment: .leading)
            Text(verbatim: value).font(.mono(11)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
        }
    }

    @ViewBuilder
    private var footer: some View {
        ForEach(model.cloudProxyNotes, id: \.self) { note in
            Notice(text: note, tone: .info)
        }
        if let problem = model.cloudProxyProblem { Notice(text: problem) }
    }
}
