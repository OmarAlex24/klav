import SwiftUI

/// «Vault health» (ADR 0022 §4, §6): reused, weak, old and, with the check
/// on, breached passwords, computed by `klavd` on this Mac, and «Fix my
/// reused passwords», a task the person offers an agent, as on the iPhone.
/// The agent gets the sites, never which ones share a password. While such
/// a task runs, a card shows each site as changed, in progress, pending or
/// failed. A row opens its item.
///
/// Nothing here holds a value: the report names items, hosts and reasons.
struct HealthPane: View {
    @EnvironmentObject private var model: MacModel
    @State private var report: VaultHealthInfo?
    @State private var breachCheck: Bool?
    @State private var problem: String?
    @State private var breachProblem: String?
    @State private var switching = false
    @State private var reload = 0
    /// The offer being prepared, and the running fix tasks.
    @State private var offer: ReusedOfferInfo?
    @State private var progress: [TaskProgressInfo] = []

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Vault health", detail: report.map {
                String(localized: "\(Int64($0.passwords)) passwords in \(Int64($0.items)) items")
            })
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(progress, id: \.taskId) { p in
                        FixProgressCard(progress: p).padding(.top, 16)
                    }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    if let offer {
                        OfferCard<MacModel>(offer: offer, pick: { agent in Task { await showOffer(agent) } },
                                            done: offered, cancel: { self.offer = nil })
                            .padding(.top, 16)
                    } else if let report {
                        sections(report)
                    } else if problem == nil {
                        Text("Checking your passwords…").font(.ui(14)).foregroundStyle(Palette.gris)
                    }
                }
                .frame(maxWidth: 620, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.top, 8)
                .padding(.bottom, 32)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: "\(model.generation)|\(reload)") { await load() }
        // Only while the pane is on screen and Klav is unlocked, like the
        // iPhone and the popup.
        .task(id: model.phase) {
            while model.phase == .unlocked, !Task.isCancelled {
                let now = await model.fixProgress()
                if !Task.isCancelled, now != progress { progress = now }
                try? await Task.sleep(for: HealthWords.progressEvery)
            }
        }
        // Locked: nothing of the report, the offer or the progress stays.
        .onChange(of: model.phase) { _, phase in if phase != .unlocked { forget() } }
    }

    @ViewBuilder
    private func sections(_ report: VaultHealthInfo) -> some View {
        let breaches = report.breaches
        let clean = report.reused.isEmpty && report.weak.isEmpty && report.old.isEmpty
            && !(breaches.status == "checked" && !breaches.found.isEmpty)
        if clean {
            Text("Nothing needs attention.")
                .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                .padding(.top, 18)
        }
        note("Klav checks them on this Mac; nothing leaves it.").padding(.top, clean ? 4 : 18)
        if report.skipped > 0 {
            note("\(Int64(report.skipped)) items could not be opened.").padding(.top, 4)
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
            Button("Fix my reused passwords") { Task { await showOffer(nil) } }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .fixedSize()
                .padding(.top, 14)
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

        heading(breaches.status == "checked" ? String(localized: "Breached · \(Int64(breaches.found.count))")
            : String(localized: "Breached"))
        if breaches.status == "checked" {
            if breaches.found.isEmpty {
                empty("None seen in known breaches.")
            } else {
                rows(breaches.found.map { ($0.item, String(localized: "seen \(Int64($0.count)) times")) })
            }
        } else if breaches.status == "failed" {
            Notice(text: String(localized: "The breach check failed: \(breaches.message ?? "")")).padding(.bottom, 8)
        }
        if let breachCheck {
            Toggle(isOn: Binding(get: { breachCheck }, set: { switchBreach($0) })) {
                Text("Look for breached passwords").font(.ui(14)).foregroundStyle(Palette.tinta)
            }
            .toggleStyle(SquareToggleStyle())
            .frame(minHeight: 44)
            .disabled(switching)
            note("Klav asks Have I Been Pwned (api.pwnedpasswords.com) about each password. It sends only the first 5 characters of the password’s SHA-1 hash, never the password or the whole hash, and the answer is padded so its size gives nothing away. Have I Been Pwned sees your IP address and the time. This Mac only.")
            if let breachProblem { Notice(text: breachProblem).padding(.top, 8) }
        }
    }

    private func load() async {
        do {
            let settings = try? await model.run { try $0.healthSettings() }
            breachCheck = settings?.breachCheck
            report = try await model.run { try $0.vaultHealth() }
            problem = nil
            #if DEBUG
            if Snapshot.takeFixOffer() { await showOffer("ag2") }
            #endif
        } catch KlavError.Locked {
            model.refresh()
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

    private func showOffer(_ agent: String?) async {
        do {
            offer = try await model.reusedOffer(agent: agent)
            problem = nil
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    private func offered(_ task: TaskItem) {
        offer = nil
        model.show(Toast(text: String(localized: "Offered to \(task.agent)")))
        reload += 1
        Task { progress = await model.fixProgress() }
    }

    private func switchBreach(_ on: Bool) {
        switching = true
        breachProblem = nil
        Task {
            do {
                let settings = try await model.run { try $0.setBreachCheck(on: on) }
                breachCheck = settings.breachCheck
                reload += 1
            } catch {
                breachProblem = describe(error)
            }
            switching = false
        }
    }

    private func heading(_ text: String) -> some View {
        SectionLabel(text).padding(.top, 28).padding(.bottom, 10)
    }

    private func empty(_ key: LocalizedStringKey) -> some View {
        Text(key).font(.ui(14)).foregroundStyle(Palette.gris)
    }

    private func note(_ key: LocalizedStringKey) -> some View {
        Text(key).font(.ui(12.5)).foregroundStyle(Palette.gris)
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

/// A problem: the item's tile, title and site, why on the right; a click
/// opens the item in the vault.
private struct HealthRow: View {
    @EnvironmentObject private var model: MacModel
    let item: HealthItemInfo
    let end: String?
    @State private var hovering = false

    var body: some View {
        let host = item.hosts.first
        Button {
            model.section = .vault(.all)
            model.selectedItem = item.id
        } label: {
            HStack(spacing: 12) {
                Tile(title: item.title, site: host.map { "https://\($0)" }, size: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(HealthWords.title(item))
                        .font(.ui(14, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                    Text(host ?? item.username ?? item.reference)
                        .font(.ui(12.5)).foregroundStyle(Palette.gris)
                        .lineLimit(1).truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if let end {
                    Text(end).font(.mono(11.5)).foregroundStyle(Palette.gris)
                }
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 52)
            .background(hovering ? Palette.niebla.opacity(0.6) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens the item")
    }
}
