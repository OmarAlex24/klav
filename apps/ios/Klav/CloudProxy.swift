import SwiftUI

/// Settings › Credential proxy (ADR 0051 §6.1, §6.3): Klav Cloud's proxy,
/// as `klav-client` checks it on this iPhone (the signed manifest and a
/// fresh attestation of the enclave), «Use Klav Cloud Proxy» for an
/// entitled account, and the red row with «Stop using it». Face ID first,
/// as for an approval. Shown only when there is something to say: an
/// account that doesn't use it and isn't entitled sees nothing.
struct CloudProxySection: View {
    @EnvironmentObject private var model: AppModel
    @State private var info: HostedProxyInfo?
    @State private var notes: [String] = []
    @State private var problem: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let info, info.needsAttention || CloudProxyWords.headline(info) != nil {
                VStack(alignment: .leading, spacing: 8) {
                    SectionLabel("Credential proxy")
                    content(info)
                    ForEach(notes, id: \.self) { Notice(text: $0, tone: .info) }
                    if let problem { Notice(text: problem) }
                }
                .padding(.top, 30)
            } else if let problem {
                Notice(text: problem).padding(.top, 30)
            }
        }
        .task { await load() }
    }

    @ViewBuilder
    private func content(_ info: HostedProxyInfo) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Klav Cloud").font(.ui(12, relativeTo: .caption))
                .foregroundStyle(info.needsAttention ? Palette.rojo : Palette.gris)
            if let line = CloudProxyWords.headline(info) {
                Text(verbatim: line).font(.ui(15)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let reason = CloudProxyWords.reason(info) {
                Text(verbatim: reason).font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if info.needsAttention {
                Text(verbatim: CloudProxyWords.keeps).font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris).fixedSize(horizontal: false, vertical: true)
            }
            if info.state == .notUsed {
                Text(verbatim: CloudProxyWords.useNote(replacesOwn: info.replacesOwn))
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if info.state == .verified, let seq = info.manifestSeq {
                Text(verbatim: "deploy/nitro/manifests/\(seq).json")
                    .font(.mono(12)).foregroundStyle(Palette.gris).textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 8)
        VStack(spacing: 8) {
            switch info.state {
            case .notUsed:
                Button("Use Klav Cloud Proxy") { act(.use) }
                    .buttonStyle(SecondaryButtonStyle())
            case .verified:
                Button("Stop using it") { act(.stop) }
                    .buttonStyle(SecondaryButtonStyle(danger: true))
            case .lostKeys, .revoked:
                Button("Set it up again") { act(.reset) }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Stop using it") { act(.stop) }
                    .buttonStyle(SecondaryButtonStyle(danger: true))
            case .unverified, .notEntitled, .unsupported:
                Button("Stop using it") { act(.stop) }
                    .buttonStyle(SecondaryButtonStyle(danger: true))
            case .unreachable:
                Button("Check again") { Task { await load() } }
                    .buttonStyle(SecondaryButtonStyle())
            }
        }
        .disabled(busy)
    }

    private func load() async {
        guard let service = model.service else { return }
        do {
            info = try await service.run { core, _ in try core.hostedProxy() }
            problem = nil
        } catch {
            problem = describe(error)
        }
    }

    private func act(_ action: HostedProxyAction) {
        problem = nil
        Task {
            guard let service = model.service else { return }
            guard await model.confirmPresence(CloudProxyWords.reasonFor(action)) else { return }
            busy = true
            defer { busy = false }
            do {
                let outcome = try await service.run { core, _ in try core.hostedProxyAct(action: action) }
                info = outcome.info
                notes = outcome.notes.map { AgentText.line($0, max: 300) }
            } catch {
                problem = describe(error)
            }
        }
    }
}
