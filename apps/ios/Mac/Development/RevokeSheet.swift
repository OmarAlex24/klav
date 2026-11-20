import SwiftUI

/// «Revoke…» (ADR 0033, amendment of 2026-11-10, F2): what the agent saw,
/// «Also change its projects' keys» (checked, P7), what revoking does and
/// does not, and «Revoke» in red, without Touch ID. Once revoked, the same
/// sheet follows the key change; it can be closed, and the agent's page
/// keeps saying what is left.
struct RevokeSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let agentId: String

    @State private var seen: ExposureInfo?
    @State private var proxy = false
    @State private var changeKeys = true
    @State private var problem: String?
    /// Klav locked: nothing was revoked (P12).
    @State private var locked = false

    private var flow: RevocationFlow? { model.revocationFlows[agentId] }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if locked {
                        lockedNotice
                    } else if let flow, flow.revoked || flow.stage == .revoking {
                        progress(flow)
                    } else if let seen {
                        before(seen)
                    } else if problem == nil {
                        ProgressView().controlSize(.small).padding(.top, 40).frame(maxWidth: .infinity)
                    }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            footer
        }
        .background(Palette.papel)
        .task { await load() }
    }

    private var name: String { AgentText.line(seen?.agent.name ?? "", max: 64) }

    // MARK: Before revoking

    @ViewBuilder
    private func before(_ seen: ExposureInfo) -> some View {
        Title("Revoke “\(name)”", size: 22)
        Text(verbatim: "ID \(AgentText.idPrefix(seen.agent.id))").font(.mono(11)).foregroundStyle(Palette.gris)
            .padding(.top, 4)

        SectionLabel("What it saw").padding(.top, 22).padding(.bottom, 8)
        whatItSaw(seen)

        if RevokeWords.offersKeyChange(seen) {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: $changeKeys) {
                    Text("Also change its projects’ keys").font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                }
                .toggleStyle(SquareToggleStyle())
                Text(verbatim: RevokeWords.cost(seen.cost, unknownProjects: seen.projectsUnknown))
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 22)
        }

        SectionLabel("What revoking does").padding(.top, 22).padding(.bottom, 8)
        VStack(alignment: .leading, spacing: 8) {
            point("It cuts the agent off at its next request, denies its requests waiting for you and ends its tasks.")
            point("It doesn’t undo what it already decrypted or started.")
            point("The keys of the items in its projects don’t change: what it saw there, it still has.")
            if proxy {
                point("It cuts off its sandboxes and services at their next call.")
                point("Changing the projects’ keys doesn’t change its items’ keys: run klav proxy revoke ITEM for each one, and rotate the token at the provider too.")
            }
        }
    }

    private func whatItSaw(_ seen: ExposureInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if seen.projectsUnknown {
                Text("This Mac can’t read its grant, so it can’t tell which projects’ keys it held. It may have held some.")
                    .font(.ui(13)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            } else if seen.projects.isEmpty {
                Text("It held no project’s key.").font(.ui(13)).foregroundStyle(Palette.gris)
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    Text("It held the keys of these projects, so it could read their items’ titles, usernames and addresses:")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(seen.projects, id: \.projectId) { p in
                        Text(verbatim: p.project.isEmpty ? AgentText.idPrefix(p.projectId) : "\(p.vault)/\(p.project)")
                            .font(.ui(14)).foregroundStyle(Palette.tinta)
                    }
                }
            }
            if let warning = seen.logWarning {
                Notice(text: warning, tone: .info)
            } else if seen.items.isEmpty {
                Text("The log shows no item it used.").font(.ui(13)).foregroundStyle(Palette.gris)
            } else {
                FieldBlock {
                    ForEach(Array(seen.items.enumerated()), id: \.offset) { index, item in
                        if index > 0 { Rule() }
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: item.reference ?? AgentText.idPrefix(item.itemId))
                                    .font(.ui(13)).foregroundStyle(Palette.tinta).lineLimit(1)
                                Text(verbatim: item.permissions.map(GrantWords.permission).joined(separator: ", "))
                                    .font(.ui(12)).foregroundStyle(Palette.gris)
                            }
                            Spacer(minLength: 8)
                            Tag(text: item.secret ? String(localized: "got a secret") : String(localized: "no secret"),
                                color: item.secret ? Palette.rojo : Palette.gris)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }
                }
            }
            if seen.denied > 0 {
                Text("Klav denied \(Int64(seen.denied)) of its attempts.").font(.ui(13)).foregroundStyle(Palette.gris)
            }
        }
    }

    private func point(_ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Rectangle().fill(Palette.tinta).frame(width: 5, height: 5).alignmentGuide(.firstTextBaseline) { $0[.bottom] + 3 }
            Text(text).font(.ui(13)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: While revoking

    @ViewBuilder
    private func progress(_ flow: RevocationFlow) -> some View {
        let left = model.keysLeft(of: agentId, listed: [])
        Title(flow.stage == .revoking ? "Revoking…" : "Revoked", size: 22)
        Text(flow.stage == .revoking
             ? "Klav is telling the server."
             : "“\(name)” can’t use Klav any more. Its next request is refused.")
            .font(.ui(13)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 6)
        if flow.changeKeys || flow.stage == .keysLeft, let text = RevokeWords.state(flow, left: left) {
            RevocationBand(text: text, flow: flow, left: left,
                           finish: RevokeWords.canFinish(flow, left: left) ? { Task { await model.finishKeys(of: agentId, left: left) } } : nil)
                .padding(.top, 20)
            if flow.stage == .changingKeys || left?.running == true {
                Text("You can close this: Klav keeps changing keys in the background, and the agent’s page says what is left.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 10)
            }
        }
    }

    // MARK: Locked (P12)

    @ViewBuilder
    private var lockedNotice: some View {
        Title("Unlock to revoke", size: 22)
        Text("Revoking signs with your account, which is only open while Klav is unlocked. Nothing was revoked. After you unlock, this opens again where it was.")
            .font(.ui(13)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 6)
        Text("Meanwhile, pausing every agent works while locked and stops them at once.")
            .font(.ui(13)).foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 14)
        Button("Pause every agent now") { Task { await pauseAll() } }
            .buttonStyle(SecondaryButtonStyle(compact: true))
            .fixedSize()
            .padding(.top, 10)
    }

    private func pauseAll() async {
        do { try await model.pauseAgents(minutes: nil) } catch { problem = describe(error) }
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: 10) {
            Spacer()
            if flow == nil && !locked {
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .keyboardShortcut(.cancelAction)
                    .fixedSize()
                Button("Revoke") { Task { await revoke() } }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                    .disabled(seen == nil)
                    .fixedSize()
            } else {
                Button(flow?.stage == .done ? "Done" : "Close") { dismiss() }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .keyboardShortcut(.defaultAction)
                    .fixedSize()
            }
        }
        .padding(.horizontal, 20)
        .frame(height: 64)
        .overlay(alignment: .top) { Rule() }
    }

    // MARK: Calls

    private func load() async {
        guard flow == nil else { return }
        do {
            let id = agentId
            let (seen, grant) = try await model.run { engine in
                (try engine.agentExposure(id: id), try? engine.grantEditor(id: id))
            }
            self.seen = seen
            proxy = grant?.readOnly == .proxy
        } catch KlavError.Locked {
            locked = true
            model.revokeAfterUnlock = agentId
        } catch {
            do {
                seen = try await model.exposureUnknown(of: agentId, because: error)
            } catch {
                problem = describe(error)
            }
        }
    }

    private func revoke() async {
        guard let agent = seen?.agent else { return }
        problem = nil
        do {
            try await model.revoke(agent, changeKeys: changeKeys && seen.map(RevokeWords.offersKeyChange) == true)
        } catch KlavError.Locked {
            locked = true
        } catch {
            problem = describe(error)
        }
    }
}
