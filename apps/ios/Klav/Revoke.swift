import SwiftUI

// Revoking an agent from the iPhone (ADR 0033, amendment of 2026-11-10,
// P10): «what it saw», then the revocation, written down before anything
// else, and then the projects' keys, one per call. The iPhone has no
// `klavd`: the app itself takes the steps while Klav is unlocked. Killed or
// locked halfway, its sealed record (`revocations.bin`) keeps what is left,
// and the next unlock picks it up again. Changing permissions comes later.

/// How this iPhone's last run of an agent's key change ended.
enum KeyChangeEnd: Equatable {
    /// Nothing left. `projects`: the projects' keys were asked to change;
    /// `skipped`: keys out of Klav's reach along the way.
    case done(projects: Bool, skipped: Int)
    /// A step failed: why.
    case stopped(String)
    /// Two steps in a row moved nothing: it waits for the next unlock.
    case stalled
}

extension AppModel {
    /// This iPhone's record of the key changes it owes. The first read
    /// after an unlock picks up those left (P11): one agent after another.
    func loadRevocations() async {
        guard let service, phase == .unlocked else { return }
        do {
            let list = try await service.run { core, _ in try core.agentRevocations() }
            guard phase == .unlocked else { return }
            if list != revocations { revocations = list }
            revocationsProblem = nil
        } catch KlavError.Locked {
            return
        } catch {
            revocationsProblem = describe(error)
            return
        }
        guard !resumedKeyChanges else { return }
        resumedKeyChanges = true
        let left = revocations.filter(KeyChangeState.resumes).map(\.agentId)
        guard !left.isEmpty else { return }
        Task {
            for id in left { await finishKeys(of: id) }
        }
    }

    /// «Revoke»: the agent is revoked and written down first, with no
    /// presence (ADR 0014 §7.1). With `changeKeys`, its projects' keys
    /// change after that, one per call.
    func revoke(agentId: String, changeKeys: Bool) async throws {
        guard let service else { return }
        let report = try await service.run { core, _ in try core.revokeAgentFirst(id: agentId, rotate: changeKeys) }
        keyChangeEnds[agentId] = nil
        show(Toast(text: String(localized: "Revoked.")))
        await loadRequests()
        if let why = report.failed {
            keyChangeEnds[agentId] = .stopped(why)
        } else if changeKeys {
            // Apart: the sheet closes on «Revoked», and the agent's page
            // follows the steps.
            let skipped = report.skipped
            Task { await finishKeys(of: agentId, changeKeys: true, skipped: skipped) }
        }
    }

    /// «Finish», or the pick-up after an unlock: one step per call until
    /// nothing is left, a step fails, or two steps in a row move nothing
    /// (`moved`, as `klavd` stops). Locking stops it; every step is
    /// written down before it answers, so nothing is lost. `changeKeys`:
    /// what the person chose, when this run starts from «Revoke»; the
    /// pick-up and «Finish» read it from the record.
    func finishKeys(of id: String, changeKeys: Bool? = nil, skipped first: [String] = []) async {
        guard let service, phase == .unlocked, !changingKeys.contains(id) else { return }
        changingKeys.insert(id)
        keyChangeEnds[id] = nil
        // A project's key changes only when it was asked (P7); Rust keeps
        // to the record whatever this says. These are only the words at
        // the end: with nothing to read, they claim no project.
        let projects = changeKeys
            ?? revocations.first { $0.agentId == id }.map(KeyChangeState.asksProjects)
            ?? false
        var skipped = Set(first)
        var idle = 0
        var end: KeyChangeEnd?
        while phase == .unlocked {
            let step: RevocationStepInfo
            do {
                step = try await service.run { core, _ in try core.revocationStep(id: id) }
            } catch KlavError.Locked {
                break
            } catch {
                end = .stopped(describe(error))
                break
            }
            skipped.formUnion(step.skipped)
            await loadRevocations()
            if let why = step.failed {
                end = .stopped(why)
                break
            }
            if step.done {
                end = .done(projects: projects, skipped: skipped.count)
                break
            }
            idle = step.moved ? 0 : idle + 1
            if idle >= 2 {
                appLog.error("key change for agent \(id, privacy: .public) made no progress twice in a row")
                end = .stalled
                break
            }
        }
        changingKeys.remove(id)
        if let end { keyChangeEnds[id] = end }
        await loadRevocations()
    }
}

/// What a revocation's key change reads as on the iPhone. Only this
/// iPhone's record: a key change another device's `klavd` is finishing is
/// in that device's record, and here the agent only reads «Revoked».
/// Never «every key it can reach» from the record: what is left there is
/// only counted.
enum KeyChangeState {
    /// The state, or nil when there is nothing to say past «Revoked».
    static func text(_ left: RevocationInfo?, running: Bool, end: KeyChangeEnd?) -> String? {
        // The iPhone never narrows a grant (P10): a narrowing in the record
        // came from elsewhere, and «Revoked» words would be wrong for it.
        if let left, left.narrowed { return nil }
        if running {
            if let left, asksProjects(left) {
                return String(localized: "Revoked. Changing keys: \(Int64(left.rotated)) of \(Int64(left.projects)) projects")
            }
            return String(localized: "Revoked. Changing keys…")
        }
        if let left { return revocation(left) }
        switch end {
        case let .done(projects, skipped)?:
            if skipped > 0 { return outOfReach(skipped, projects: projects) }
            return projects
                ? String(localized: "Revoked. Done: every key changed.")
                : String(localized: "Revoked. The items shared with it one by one have new keys.")
        case .stopped?, .stalled?, nil:
            return nil
        }
    }

    /// What the record says is left, most pressing first.
    private static func revocation(_ left: RevocationInfo) -> String {
        if left.unknownProjects {
            return String(localized: "Revoked. Klav doesn’t know which projects it had.")
        }
        if left.toChange > 0 {
            return String(localized: "Revoked. Keys left to change (\(Int64(left.toChange)) of \(Int64(left.projects)))")
        }
        if left.items > 0 {
            return String(localized: "Revoked. Some items shared with it one by one still need a new key.")
        }
        if left.regrants > 0 {
            return String(localized: "Revoked. Other agents still need their new grant.")
        }
        if left.logUnchecked {
            return String(localized: "Revoked. Klav hasn’t read the audit log yet, which lists every project it had.")
        }
        if left.skipped > 0 { return outOfReach(Int(left.skipped), projects: asksProjects(left)) }
        return String(localized: "Revoked. Keys left to change")
    }

    /// Keys out of reach. Without projects, only items shared one by one
    /// were in it: never a word about projects (P7).
    private static func outOfReach(_ skipped: Int, projects: Bool) -> String {
        if projects {
            return String(localized: "Revoked. \(Int64(skipped)) keys are out of Klav’s reach, so they didn’t change (their vault or project is gone, or this iPhone no longer sees them).")
        }
        return String(localized: "Revoked. \(Int64(skipped)) items shared with it one by one are out of Klav’s reach, so their keys didn’t change (their vault is gone, or this iPhone no longer sees them). If one comes back, Klav changes its key the next time you unlock, or when you tap Finish; an item deleted for good never comes back.")
    }

    /// Why it stopped, if it did.
    static func problem(_ left: RevocationInfo?, end: KeyChangeEnd?) -> String? {
        if case .stalled? = end {
            return String(localized: "Klav stopped changing keys because it made no progress. It tries again the next time you unlock.")
        }
        if case let .stopped(why)? = end { return String(localized: "The key change stopped: \(why)") }
        if let why = left?.lastError { return String(localized: "The key change stopped: \(why)") }
        return nil
    }

    /// «Finish» goes on with what is left, and only with what can move
    /// without the person deciding (unknown projects wait, T189).
    static func canFinish(_ left: RevocationInfo?, running: Bool) -> Bool {
        guard let left, !running else { return false }
        return left.needsWork && !left.narrowed
    }

    /// The person asked for the projects' keys to change: `status` says a
    /// revocation without it is one (#308), and the record counts projects
    /// only for one with it.
    static func asksProjects(_ left: RevocationInfo) -> Bool {
        !left.withoutKeyChange && left.projects > 0
    }

    /// Picked up after an unlock (P11).
    static func resumes(_ left: RevocationInfo) -> Bool {
        left.needsWork && !left.narrowed && !left.unknownProjects
    }
}

extension AppModel {
    /// The key change's state for agent `id`, if any.
    func keyChangeText(_ id: String) -> String? {
        KeyChangeState.text(revocations.first { $0.agentId == id },
                            running: changingKeys.contains(id), end: keyChangeEnds[id])
    }
}

/// The key change under a revoked agent's header: what is left, why it
/// stopped, and «Finish».
struct KeyChangeBand: View {
    @EnvironmentObject private var model: AppModel
    let agentId: String

    private var left: RevocationInfo? { model.revocations.first { $0.agentId == agentId } }
    private var running: Bool { model.changingKeys.contains(agentId) }

    var body: some View {
        let end = model.keyChangeEnds[agentId]
        if let text = KeyChangeState.text(left, running: running, end: end) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    if running { ProgressView().controlSize(.small) }
                    Text(verbatim: text)
                        .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("key-change-state")
                }
                if let skipped = left?.skippedProjects, !skipped.isEmpty, !running {
                    Text(verbatim: skipped.joined(separator: "\n"))
                        .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                if running {
                    Text("Keep Klav open until it’s done. If it closes or locks, Klav picks up where it left off the next time you unlock.")
                        .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let problem = KeyChangeState.problem(left, end: end), !running {
                    Notice(text: problem)
                }
                if KeyChangeState.canFinish(left, running: running) {
                    Button("Finish") { Task { await model.finishKeys(of: agentId) } }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .fixedSize()
                        .accessibilityIdentifier("key-change-finish")
                }
            }
        } else if let problem = model.revocationsProblem {
            Notice(text: String(localized: "Klav can’t read its record of the key changes it owes, so it can’t tell what is left: \(problem)"))
                .padding(.top, 14)
        }
    }
}

/// «Revoke…» (F2): what the agent saw, «Also change its projects’ keys»
/// (on, P7) with what it costs, what revoking does, and «Revoke» in red,
/// with no Face ID. The agent's page follows the key change after it.
struct AgentRevokeSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let agentId: String
    let name: String

    @State private var seen: ExposureInfo?
    /// What it saw can't be read: it can still be revoked, and the key
    /// change looks for its projects in what the account signed.
    @State private var unread: String?
    @State private var changeKeys = true
    @State private var busy = false
    @State private var problem: String?

    private var offersKeyChange: Bool { seen.map(KeyChangeWords.offersKeyChange) ?? (unread != nil) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Title("Revoke “\(AgentText.line(name, max: 64))”", size: 22)
                Text(verbatim: "ID " + AgentText.idPrefix(agentId))
                    .font(.mono(12)).foregroundStyle(Palette.gris)
                    .padding(.top, 4)
                SectionLabel("What it saw").padding(.top, 22).padding(.bottom, 8)
                if let seen {
                    whatItSaw(seen)
                } else if let unread {
                    Notice(text: unread, tone: .info)
                } else {
                    ProgressView().frame(maxWidth: .infinity).padding(.vertical, 20)
                }
                if offersKeyChange {
                    VStack(alignment: .leading, spacing: 6) {
                        Toggle(isOn: $changeKeys) {
                            Text("Also change its projects’ keys").font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                        }
                        .toggleStyle(SquareToggleStyle())
                        .accessibilityIdentifier("revoke-change-keys")
                        Text(verbatim: seen.map { KeyChangeWords.cost($0.cost, unknownProjects: $0.projectsUnknown) }
                             ?? KeyChangeWords.cost(KeyChangeCostInfo(items: 0, otherAgents: [], itemsAtLeast: true, othersAtLeast: true),
                                                    unknownProjects: true))
                            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.top, 22)
                }
                SectionLabel("What revoking does").padding(.top, 22).padding(.bottom, 8)
                VStack(alignment: .leading, spacing: 8) {
                    point("It cuts the agent off at its next request, denies its requests waiting for you and ends its tasks.")
                    point("It doesn’t undo what it already decrypted or started.")
                    point("The keys of the items in its projects don’t change: what it saw there, it still has.")
                }
                if let problem { Notice(text: problem).padding(.top, 16) }
                VStack(spacing: 10) {
                    Button(busy ? String(localized: "Revoking…") : String(localized: "Revoke")) { Task { await revoke() } }
                        .buttonStyle(SecondaryButtonStyle(danger: true))
                        .disabled(busy || (seen == nil && unread == nil))
                        .accessibilityIdentifier("revoke-confirm")
                    Button("Cancel") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(busy)
                }
                .padding(.top, 24)
            }
            .padding(24)
        }
        .background(Palette.papel)
        .interactiveDismissDisabled(busy)
        .task { await load() }
    }

    private func whatItSaw(_ seen: ExposureInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if seen.projectsUnknown {
                Text("This iPhone can’t read its grant, so it can’t tell which projects’ keys it held. It may have held some.")
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            } else if seen.projects.isEmpty {
                Text("It held no project’s key.").font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    Text("It held the keys of these projects, so it could read their items’ titles, usernames and addresses:")
                        .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(seen.projects, id: \.projectId) { p in
                        Text(verbatim: p.project.isEmpty ? AgentText.idPrefix(p.projectId) : "\(p.vault)/\(p.project)")
                            .font(.ui(15)).foregroundStyle(Palette.tinta)
                    }
                }
            }
            if let warning = seen.logWarning {
                Notice(text: warning, tone: .info)
            } else if seen.items.isEmpty {
                Text("The log shows no item it used.").font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
            } else {
                FieldBlock {
                    ForEach(Array(seen.items.enumerated()), id: \.offset) { index, item in
                        if index > 0 { Rule() }
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: item.reference ?? AgentText.idPrefix(item.itemId))
                                    .font(.ui(14)).foregroundStyle(Palette.tinta).lineLimit(1)
                                Text(verbatim: item.permissions.map(ActivityWords.permissionName).joined(separator: ", "))
                                    .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
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
                Text("Klav denied \(Int64(seen.denied)) of its attempts.")
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
            }
        }
    }

    private func point(_ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Rectangle().fill(Palette.tinta).frame(width: 5, height: 5).alignmentGuide(.firstTextBaseline) { $0[.bottom] + 3 }
            Text(text).font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        let id = agentId
        do {
            seen = try await service.run { core, _ in try core.agentExposure(id: id) }
        } catch KlavError.Locked {
            model.lock()
            dismiss()
        } catch {
            unread = String(localized: "Klav can’t read what it saw right now (\(describe(error))). Revoking still works.")
        }
    }

    private func revoke() async {
        busy = true
        problem = nil
        do {
            try await model.revoke(agentId: agentId, changeKeys: changeKeys && offersKeyChange)
            dismiss()
        } catch KlavError.Locked {
            model.lock()
            dismiss()
        } catch {
            problem = describe(error)
            busy = false
        }
    }
}
