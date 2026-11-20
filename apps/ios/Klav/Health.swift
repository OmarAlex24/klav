import SwiftUI

/// «Vault health» (ADR 0022 §4, §6), as the extension's popup tells it:
/// reused, weak, old and, if the person turned the check on, breached
/// passwords, computed on this iPhone; and «Fix my reused passwords», a
/// task the person offers an agent. The agent gets the sites, never which
/// ones share a password. While such a task runs, a card shows each site as
/// changed, in progress, pending or failed.
///
/// Nothing here holds a value: the report names items, hosts and reasons.

/// The screen, from Settings › Passwords. A stack of its own, so a problem
/// opens its item.
struct HealthView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var report: VaultHealthInfo?
    @State private var breachCheck: Bool?
    @State private var problem: String?
    @State private var offer: ReusedOfferInfo?
    @State private var progress: [TaskProgressInfo] = []
    @State private var reload = 0

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    Title("Vault health", size: 22)
                    Spacer()
                    Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
                }
                .padding(.horizontal, 20)
                .frame(minHeight: 64)
                .overlay(alignment: .bottom) { Rule() }
                ScrollViewReader { scroller in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(progress, id: \.taskId) { p in
                                FixProgressCard(progress: p).padding(.top, 16)
                            }
                            if let problem {
                                Notice(text: problem).padding(.top, 16)
                            }
                            if let offer {
                                OfferCard<AppModel>(offer: offer, pick: { agent in Task { await showOffer(agent) } },
                                          done: offered, cancel: { self.offer = nil })
                                    .padding(.top, 16)
                                    .id("offer")
                            } else if let report {
                                HealthSections(report: report, breachCheck: breachCheck,
                                               fix: { Task { await showOffer(nil) } },
                                               setBreach: setBreach)
                            } else if problem == nil {
                                Text("Checking your passwords…")
                                    .font(.ui(15)).foregroundStyle(Palette.gris)
                                    .padding(.top, 24)
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 40)
                    }
                    .onChange(of: offer) { _, now in
                        if now != nil { withAnimation { scroller.scrollTo("offer", anchor: .top) } }
                    }
                }
            }
            .background(Palette.papel)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: String.self) { id in ItemView(id: id) }
        }
        .task(id: "\(model.generation)|\(reload)") { await load() }
        // Locked: nothing of the report, the offer or the progress stays.
        // The sheet goes with the vault; this covers the moment before.
        .onChange(of: model.phase) { _, phase in
            if phase != .unlocked { forget() }
        }
        // Only while on screen, like the popup.
        .task(id: model.inForeground) {
            while model.inForeground, !Task.isCancelled {
                await refreshProgress()
                try? await Task.sleep(for: HealthWords.progressEvery)
            }
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        do {
            let settings = try? await service.run { core, _ in try core.healthSettings() }
            breachCheck = settings?.breachCheck
            report = try await service.run { core, _ in try core.vaultHealth() }
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
    }

    private func forget() {
        report = nil
        breachCheck = nil
        offer = nil
        progress = []
        problem = nil
    }

    private func refreshProgress() async {
        guard let service = model.service else { return }
        // Progress is optional here: a failed read keeps the last one.
        guard let tasks = try? await service.run({ core, _ in try core.tasks() }) else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var list: [TaskProgressInfo] = []
        for task in tasks where HealthWords.isFixTask(task, now: now) {
            let id = task.id
            if let p = try? await service.run({ core, _ in try core.taskProgress(taskId: id) }) { list.append(p) }
        }
        if list != progress { progress = list }
    }

    private func showOffer(_ agent: String?) async {
        guard let service = model.service else { return }
        do {
            offer = try await service.run { core, _ in try core.reusedOffer(agent: agent) }
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
    }

    private func offered(_ task: TaskItem) {
        offer = nil
        model.show(Toast(text: String(localized: "Offered to \(task.agent)")))
        reload += 1
        Task { await refreshProgress() }
    }

    private func setBreach(_ on: Bool) async throws {
        guard let service = model.service else { return }
        let settings = try await service.run { core, _ in try core.setBreachCheck(on: on) }
        breachCheck = settings.breachCheck
        report = nil
        reload += 1
    }
}

/// The report's sections: reused (with «Fix my reused passwords»), weak,
/// old and breached, with the breach check's switch and what it sends.
struct HealthSections: View {
    let report: VaultHealthInfo
    let breachCheck: Bool?
    let fix: () -> Void
    let setBreach: (Bool) async throws -> Void

    @State private var breachProblem: String?
    @State private var switching = false

    private var clean: Bool {
        report.reused.isEmpty && report.weak.isEmpty && report.old.isEmpty
            && !(report.breaches.status == "checked" && !report.breaches.found.isEmpty)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if clean {
                Text("Nothing needs attention.")
                    .font(.ui(17, .medium, relativeTo: .headline))
                    .foregroundStyle(Palette.tinta)
                    .padding(.top, 22)
            }
            note(Text("Checked \(Int64(report.passwords)) passwords in \(Int64(report.items)) items. Klav does it on this iPhone; nothing leaves it."))
                .padding(.top, clean ? 6 : 22)
            if report.skipped > 0 {
                note(Text("\(Int64(report.skipped)) items could not be opened.")).padding(.top, 4)
            }

            heading(String(localized: "Reused · \(Int64(report.reused.count))"))
            if report.reused.isEmpty {
                empty("No password is used in two places.")
            } else {
                ForEach(Array(report.reused.enumerated()), id: \.offset) { index, group in
                    FieldLabel(String(localized: "Same password in \(Int64(group.items.count)) items"))
                        .padding(.top, index == 0 ? 0 : 14)
                        .padding(.bottom, 6)
                    rows(group.items.map { ($0, nil) })
                }
                Button("Fix my reused passwords", action: fix)
                    .buttonStyle(PrimaryButtonStyle())
                    .padding(.top, 16)
                    .accessibilityIdentifier("health-fix")
            }

            heading(String(localized: "Weak · \(Int64(report.weak.count))"))
            if report.weak.isEmpty {
                empty("No weak password.")
            } else {
                rows(report.weak.map { w in
                    let end = w.generatedBits.map { $0 < 40 ? String(localized: "\(Int64($0)) bits") : nil } ?? nil
                    return (w.item, end ?? String(localized: "strength \(Int64(w.score))/4"))
                })
            }

            heading(String(localized: "Old · \(Int64(report.old.count))"))
            if report.old.isEmpty {
                empty("None unchanged for over a year.")
            } else {
                rows(report.old.map { ($0.item, String(localized: "since \(HealthWords.day($0.sinceMs))")) })
            }

            breached
        }
    }

    @ViewBuilder
    private var breached: some View {
        let b = report.breaches
        heading(b.status == "checked" ? String(localized: "Breached · \(Int64(b.found.count))")
            : String(localized: "Breached"))
        if b.status == "checked" {
            if b.found.isEmpty {
                empty("None seen in known breaches.")
            } else {
                rows(b.found.map { ($0.item, String(localized: "seen \(Int64($0.count)) times")) })
            }
        } else if b.status == "failed" {
            Notice(text: String(localized: "The breach check failed: \(b.message ?? "")")).padding(.bottom, 8)
        }
        if let breachCheck {
            Toggle(isOn: Binding(get: { breachCheck }, set: { on in switchBreach(on) })) {
                Text("Look for breached passwords").font(.ui(16)).foregroundStyle(Palette.tinta)
            }
            .toggleStyle(SquareToggleStyle())
            .frame(minHeight: 52)
            .disabled(switching)
            .accessibilityIdentifier("health-breach")
            note(Text("Klav asks Have I Been Pwned (api.pwnedpasswords.com) about each password. It sends only the first 5 characters of the password’s SHA-1 hash, never the password or the whole hash, and the answer is padded so its size gives nothing away. Have I Been Pwned sees your IP address and the time. This iPhone only."))
            if let breachProblem { Notice(text: breachProblem).padding(.top, 8) }
        }
    }

    private func switchBreach(_ on: Bool) {
        switching = true
        breachProblem = nil
        Task {
            do { try await setBreach(on) } catch { breachProblem = describe(error) }
            switching = false
        }
    }

    private func heading(_ text: String) -> some View {
        SectionLabel(text).padding(.top, 30).padding(.bottom, 10)
    }

    private func empty(_ key: LocalizedStringKey) -> some View {
        Text(key).font(.ui(15)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func note(_ text: Text) -> some View {
        text.font(.ui(13, relativeTo: .footnote))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func rows(_ list: [(HealthItemInfo, String?)]) -> some View {
        FieldBlock {
            ForEach(Array(list.enumerated()), id: \.offset) { index, entry in
                if index > 0 { Rule() }
                HealthRow(item: entry.0, end: entry.1)
            }
        }
    }
}

/// A problem: the item's tile, title and site, why on the right, and a tap
/// opens the item.
struct HealthRow: View {
    let item: HealthItemInfo
    let end: String?
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let host = item.hosts.first
        NavigationLink(value: item.id) {
            HStack(spacing: 12) {
                Tile(title: item.title, site: host.map { "https://\($0)" })
                VStack(alignment: .leading, spacing: 2) {
                    Text(HealthWords.title(item))
                        .font(.ui(16, .medium))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                    Text(host ?? item.username ?? item.reference)
                        .font(.ui(14, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if typeSize.isAccessibilitySize, let end {
                        Text(end).font(.mono(13)).foregroundStyle(Palette.gris)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if !typeSize.isAccessibilitySize, let end {
                    Text(end).font(.mono(12.5)).foregroundStyle(Palette.gris)
                }
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 60)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowButtonStyle())
        .accessibilityElement(children: .combine)
    }
}

/// «Pending change: did the new password work?» on an item whose assisted
/// change nobody confirmed (ADR 0022 §5). Both passwords are saved; the
/// person picks one, and the other goes to Previous passwords.
struct PendingChangeCard: View {
    @EnvironmentObject private var model: AppModel
    let id: String
    let since: Int64?
    let decided: () -> Void

    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        AgentCard {
            AgentMark(text: "Pending change: did the new password work?")
                .accessibilityAddTraits(.isHeader)
            Group {
                if let since {
                    Text("An agent changed this password on its site on \(HealthWords.day(since)) and nobody confirmed whether the site took the new one. Both are saved.")
                } else {
                    Text("An agent changed this password on its site and nobody confirmed whether the site took the new one. Both are saved.")
                }
            }
            .font(.ui(14, relativeTo: .subheadline))
            .foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
            if let problem { Notice(text: problem).padding(.top, 4) }
            Flow(spacing: 8) {
                Button("Use the new one") { decide(true) }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .accessibilityIdentifier("pending-use-new")
                Button("Keep the current one") { decide(false) }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityIdentifier("pending-keep")
            }
            .padding(.top, 6)
        }
        .disabled(busy)
    }

    private func decide(_ accept: Bool) {
        guard let service = model.service else { return }
        busy = true
        problem = nil
        let id = id
        Task {
            do {
                _ = try await service.run { core, _ in try core.resolvePending(id: id, accept: accept) }
                model.show(Toast(text: accept
                    ? String(localized: "The new password is now current; the old one is in Previous passwords")
                    : String(localized: "The current one stays; the new one is in Previous passwords")))
                decided()
            } catch KlavError.Locked {
                model.lock()
            } catch {
                problem = describe(error)
            }
            busy = false
        }
    }
}
