import SwiftUI

/// Development › Activity (ADR 0033 §8.1, ⌘5): the account's audit log,
/// newest first, grouped by day, with its filters and the state of the
/// chain on top. It comes from `klavd`'s cached copy (§8.4): opening it
/// downloads only what is new, and «Verify now» checks every signature.
struct ActivityPane: View {
    @EnvironmentObject private var model: MacModel
    @State private var lines: [LogEntryInfo] = []
    @State private var status: AuditStatusInfo?
    @State private var loaded = false
    @State private var problem: String?
    @State private var verifying = false
    @State private var verifyNote: String?

    @State private var text = ""
    @State private var permissions: Set<String> = []
    @State private var outcomes: Set<String> = []
    @State private var alertsOnly = false
    @State private var period: Period = .all
    @FocusState private var searching: Bool

    static let limit: UInt32 = 500

    /// Shared with the iPhone's Activity.
    typealias Period = ActivityPeriod

    /// Reloads when any filter or the account's state moves.
    private struct Key: Equatable {
        let generation: Int, text: String, permissions: Set<String>, outcomes: Set<String>
        let alerts: Bool, period: Period, item: String?, agent: String?
    }

    private var key: Key {
        Key(generation: model.generation, text: text, permissions: permissions, outcomes: outcomes,
            alerts: alertsOnly, period: period, item: model.activityItem, agent: model.activityAgent)
    }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Activity", detail: loaded ? count : nil)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    chain
                    filters.padding(.top, 18)
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    if loaded && lines.isEmpty { empty.padding(.top, 28) }
                    ForEach(days, id: \.0) { day, entries in
                        SectionLabel(day).padding(.top, 26).padding(.bottom, 10)
                        FieldBlock {
                            ForEach(Array(entries.enumerated()), id: \.element.seq) { index, entry in
                                if index > 0 { Rule() }
                                ActivityRow(entry: entry)
                            }
                        }
                    }
                    if lines.count >= Int(Self.limit) {
                        Text("Showing the newest \(Int64(Self.limit)). Narrow the filters, or use klav log in the terminal for the rest.")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .padding(.top, 16)
                    }
                }
                .frame(maxWidth: 720, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: key) { await load(debounce: !text.isEmpty) }
    }

    private var count: String {
        lines.count == 1 ? String(localized: "1 event") : String(localized: "\(Int64(lines.count)) events")
    }

    /// The events by day, newest first.
    private var days: [(String, [LogEntryInfo])] { ActivityWords.days(lines) }

    // MARK: The chain

    private var chain: some View {
        HStack(alignment: .center, spacing: 12) {
            IconView(icon: status?.verified != nil && status?.unverified == 0 ? .check : .list, size: 16)
                .foregroundStyle(Palette.tinta)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: chainTitle).font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                Text(verbatim: verifyNote ?? String(localized: "Verifying checks every signature in the chain and signs where this Mac got to, so the server can’t rewrite what it already saw."))
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            Button(verifying ? String(localized: "Verifying…") : String(localized: "Verify now")) {
                Task { await verify() }
            }
            .buttonStyle(SecondaryButtonStyle(compact: true))
            .fixedSize()
            .disabled(verifying)
        }
        .padding(14)
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
    }

    private var chainTitle: String {
        guard let status else { return String(localized: "The log") }
        guard let verified = status.verified else {
            return String(localized: "This Mac hasn’t verified the log yet")
        }
        if status.unverified == 0 { return String(localized: "Verified up to event #\(Int64(verified))") }
        return String(localized: "Verified up to event #\(Int64(verified)) · \(Int64(status.unverified)) not verified yet")
    }

    private func verify() async {
        verifying = true
        problem = nil
        do {
            let report = try await model.run { try $0.verifyAudit() }
            verifyNote = ActivityWords.checked(report)
            await load(debounce: false)
        } catch {
            problem = describe(error)
        }
        verifying = false
    }

    // MARK: Filters

    private var filters: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                IconView(icon: .search, size: 16).foregroundStyle(Palette.gris)
                TextField(text: $text, prompt: placeholder("Search titles, agents, reasons and sites", font: .ui(14))) {
                    Text("Search")
                }
                .textFieldStyle(.plain)
                .focused($searching)
                if !text.isEmpty {
                    Button { text = "" } label: { IconView(icon: .close, size: 14) }
                        .buttonStyle(.plain)
                        .foregroundStyle(Palette.gris)
                        .accessibilityLabel(Text("Clear the search"))
                }
            }
            .inputBox(focused: searching, font: .ui(14))
            Flow(spacing: 8) {
                if let item = model.activityItem {
                    Chip(text: String(localized: "Item: \(itemTitle(item))") + "  ×", on: true) { model.activityItem = nil }
                }
                agentMenu
                FilterMenu(title: String(localized: "Permission"), chosen: permissions.map(ActivityWords.permissionName)) {
                    ForEach(ActivityWords.permissions, id: \.self) { p in
                        Toggle(ActivityWords.permissionName(p), isOn: binding(p, in: $permissions))
                    }
                }
                FilterMenu(title: String(localized: "Result"), chosen: outcomes.map(ActivityWords.outcomeName)) {
                    ForEach(ActivityWords.outcomes, id: \.self) { o in
                        Toggle(ActivityWords.outcomeName(o), isOn: binding(o, in: $outcomes))
                    }
                }
                FilterMenu(title: String(localized: "Period"), chosen: period == .all ? [] : [period.label]) {
                    Picker(String(localized: "Period"), selection: $period) {
                        ForEach(Period.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.inline)
                }
                Chip(text: String(localized: "Only alerts"), on: alertsOnly) { alertsOnly.toggle() }
                if filtering {
                    Button("Clear filters") { clear() }
                        .buttonStyle(LinkButtonStyle())
                }
            }
        }
    }

    private var agentMenu: some View {
        let agents = model.knownAgents.values.sorted { $0.name < $1.name }
        let current = model.activityAgent.map { id in model.knownAgents[id]?.name ?? String(id.prefix(8)) }
        return FilterMenu(title: String(localized: "Agent"), chosen: current.map { [$0] } ?? []) {
            Button(String(localized: "Every agent")) { model.activityAgent = nil }
            Divider()
            ForEach(agents, id: \.id) { agent in
                Button(agent.name) { model.activityAgent = agent.id }
            }
        }
    }

    private var filtering: Bool {
        !text.isEmpty || !permissions.isEmpty || !outcomes.isEmpty || alertsOnly || period != .all
            || model.activityItem != nil || model.activityAgent != nil
    }

    private func clear() {
        text = ""
        permissions = []
        outcomes = []
        alertsOnly = false
        period = .all
        model.activityItem = nil
        model.activityAgent = nil
    }

    private func binding(_ value: String, in set: Binding<Set<String>>) -> Binding<Bool> {
        Binding(get: { set.wrappedValue.contains(value) },
                set: { on in if on { set.wrappedValue.insert(value) } else { set.wrappedValue.remove(value) } })
    }

    private func itemTitle(_ id: String) -> String {
        lines.first { $0.itemId == id }.flatMap(ActivityWords.title) ?? String(localized: "this one")
    }

    private var empty: some View {
        HStack(alignment: .top, spacing: 18) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 40, height: 88)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(filtering ? "Nothing matches these filters" : "Nothing in the log yet")
                    .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                Text("Every use of an item by an agent, and every decision of yours, is written in the account’s audit log. The server can’t change an event without this Mac noticing.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                if filtering {
                    Button("Clear filters") { clear() }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .fixedSize()
                        .padding(.top, 6)
                }
            }
        }
    }

    // MARK: Loading

    private func load(debounce: Bool) async {
        if debounce {
            try? await Task.sleep(for: .milliseconds(250))
            if Task.isCancelled { return }
        }
        let search = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let filter = LogFilterInput(item: model.activityItem, agent: model.activityAgent, vault: nil,
                                    sinceMs: period.since(), untilMs: nil, alerts: alertsOnly,
                                    permissions: Array(permissions).sorted(), outcomes: Array(outcomes).sorted(),
                                    text: search.isEmpty ? nil : search, limit: Self.limit)
        do {
            let found = try await model.run { try $0.auditLog(filter: filter) }
            if Task.isCancelled { return }
            lines = found
            status = try? await model.run { try $0.auditStatus() }
            problem = nil
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

/// An agent's reason in one line, in quotes, and «(according to the
/// agent)» apart from it (T136): in a narrow window the reason gives way,
/// never the marker.
struct ReasonLine: View {
    let reason: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Text(verbatim: "“" + ActivityWords.shown(reason))
                .lineLimit(1)
                .truncationMode(.tail)
            Text(verbatim: "”").fixedSize()
            Text("(according to the agent)")
                .fixedSize()
                .padding(.leading, 4)
                .layoutPriority(1)
        }
        .font(.ui(12.5)).foregroundStyle(Palette.gris)
    }
}

/// One event: when, who did what to which item, the agent's reason in
/// quotes (T136), the outcome and the alerts, and «Not verified yet» past
/// the last head this Mac verified.
struct ActivityRow: View {
    @EnvironmentObject private var model: MacModel
    let entry: LogEntryInfo
    /// In «Who used it» the item is the one on screen.
    var showsItem = true

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 14) {
            Text(verbatim: ActivityWords.clock(entry.atMs))
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .monospacedDigit()
                .frame(width: 58, alignment: .leading)
            VStack(alignment: .leading, spacing: 3) {
                ActivityWords.sentence(entry, size: 13.5)
                    .fixedSize(horizontal: false, vertical: true)
                if showsItem, let title = ActivityWords.title(entry) {
                    Text(verbatim: place(title))
                        .font(.ui(12.5)).foregroundStyle(Palette.tinta.opacity(0.8))
                        .lineLimit(1)
                }
                if let reason = entry.reason, !reason.isEmpty {
                    ReasonLine(reason: reason)
                }
            }
            Spacer(minLength: 12)
            tags
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .contentShape(Rectangle())
        .contextMenu {
            if let id = entry.itemId, entry.item != nil {
                Button("Show the item") {
                    model.selectedItem = id
                    model.section = .vault(.all)
                }
                Button("Only this item") { model.openActivity(item: id, agent: model.activityAgent) }
            }
            if let agent = entry.agentId {
                Button("Only this agent") { model.openActivity(item: model.activityItem, agent: agent) }
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// «GitHub · Work / Release» when the reference has a place.
    private func place(_ title: String) -> String {
        guard let reference = entry.item, let place = RequestWords.target(reference).where else { return title }
        return "\(title) · \(place)"
    }

    @ViewBuilder
    private var tags: some View {
        HStack(spacing: 6) {
            if let (text, tone) = ActivityWords.outcome(entry) {
                Tag(text: text, color: tone == .denied ? Palette.rojo : Palette.cobalto)
            }
            ForEach(entry.alerts.filter { $0 != "denied" || entry.outcome != "deny" }, id: \.self) { alert in
                Tag(text: ActivityWords.alert(alert), color: alert == "first_use" ? Palette.tinta : Palette.rojo)
            }
            if !entry.verified {
                Tag(text: String(localized: "Not verified yet"), color: Palette.gris)
            }
        }
        .fixedSize()
    }
}
