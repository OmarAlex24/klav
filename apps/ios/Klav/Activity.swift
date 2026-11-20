import SwiftUI

/// The filters of Activity: what the log is narrowed to, as `klav-client`
/// reads it (ADR 0033 §8.1).
struct ActivityFilter: Equatable {
    var text = ""
    var permissions: Set<String> = []
    var outcomes: Set<String> = []
    var alertsOnly = false
    var period: ActivityPeriod = .all
    var item: String?
    var agent: String?

    /// The newest ones; the rest are in `klav log`.
    static let limit: UInt32 = 300

    func input(now: Date = Date()) -> LogFilterInput {
        let search = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return LogFilterInput(item: item, agent: agent, vault: nil, sinceMs: period.since(now: now), untilMs: nil,
                              alerts: alertsOnly, permissions: permissions.sorted(), outcomes: outcomes.sorted(),
                              text: search.isEmpty ? nil : search, limit: Self.limit)
    }

    var filtering: Bool {
        !text.isEmpty || !permissions.isEmpty || !outcomes.isEmpty || alertsOnly || period != .all
            || item != nil || agent != nil
    }

    mutating func clear() { self = ActivityFilter() }
}

/// The state of the chain, on top of Activity (ADR 0033 §8.4).
enum ChainWords {
    static func title(_ status: AuditStatusInfo?) -> String {
        guard let status else { return String(localized: "The log") }
        guard let verified = status.verified else { return String(localized: "This iPhone hasn’t verified the log yet") }
        if status.unverified == 0 { return String(localized: "Verified up to event #\(Int64(verified))") }
        return String(localized: "Verified up to event #\(Int64(verified)) · \(Int64(status.unverified)) not verified yet")
    }

    static var explanation: String {
        String(localized: "Verifying checks every signature in the chain and signs where this iPhone got to, so the server can’t rewrite what it already saw.")
    }

    static func verified(_ status: AuditStatusInfo?) -> Bool {
        status?.verified != nil && status?.unverified == 0
    }
}

/// Activity (ADR 0033 §8.1, §9): the account's audit log, newest first, by
/// day, with the state of the chain on top and filters by agent, text,
/// permission and result. From Agents, or from an item's «Who used it»
/// already narrowed to the item.
struct ActivityView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var filter: ActivityFilter
    /// Presented over an item rather than pushed in Agents.
    let inSheet: Bool

    @State private var lines: [LogEntryInfo] = []
    @State private var status: AuditStatusInfo?
    @State private var loaded = false
    @State private var problem: String?
    @State private var verifying = false
    @State private var verifyNote: String?
    @FocusState private var searching: Bool

    init(item: String? = nil, agent: String? = nil, inSheet: Bool = false) {
        _filter = State(initialValue: ActivityFilter(item: item, agent: agent))
        self.inSheet = inSheet
    }

    private struct Key: Equatable {
        let generation: Int
        let filter: ActivityFilter
    }

    var body: some View {
        VStack(spacing: 0) {
            if inSheet {
                HStack {
                    Title("Activity", size: 22)
                    Spacer()
                    Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
                }
                .padding(.horizontal, 20)
                .frame(minHeight: 64)
                .overlay(alignment: .bottom) { Rule() }
            } else {
                BackBar(title: "Agents")
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if !inSheet {
                        Title("Activity").padding(.bottom, 16)
                    }
                    chain
                    filters.padding(.top, 18)
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    if loaded && lines.isEmpty { empty.padding(.top, 28) }
                    ActivityDays(lines: lines)
                    if lines.count >= Int(ActivityFilter.limit) {
                        Text("Showing the newest \(Int64(ActivityFilter.limit)). Narrow the filters, or use klav log in the terminal for the rest.")
                            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 16)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 40)
            }
            .scrollDismissesKeyboard(.immediately)
            .refreshable {
                await model.sync(force: true)
                await load(debounce: false)
            }
        }
        .background(Palette.papel)
        .toolbar(.hidden, for: .navigationBar)
        .task(id: Key(generation: model.generation, filter: filter)) { await load(debounce: !filter.text.isEmpty) }
    }

    // MARK: The chain

    private var chain: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                IconView(icon: ChainWords.verified(status) ? .check : .list)
                    .foregroundStyle(Palette.tinta)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: ChainWords.title(status))
                        .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(verbatim: verifyNote ?? ChainWords.explanation)
                        .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Button(verifying ? String(localized: "Verifying…") : String(localized: "Verify now")) {
                Task { await verify() }
            }
            .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            .disabled(verifying)
            .accessibilityIdentifier("activity-verify")
            .padding(.leading, 26)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
    }

    private func verify() async {
        guard let service = model.service else { return }
        verifying = true
        problem = nil
        do {
            let report = try await service.run { core, _ in try core.verifyAudit() }
            verifyNote = ActivityWords.checked(report)
            await load(debounce: false)
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
        verifying = false
    }

    // MARK: Filters

    private var filters: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                IconView(icon: .search).foregroundStyle(Palette.gris)
                TextField(text: $filter.text, prompt: placeholder("Search titles, agents, reasons and sites")) {
                    Text("Search")
                }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
                .focused($searching)
                if !filter.text.isEmpty {
                    Button { filter.text = "" } label: { IconView(icon: .close, size: 14) }
                        .buttonStyle(.plain)
                        .foregroundStyle(Palette.gris)
                        .frame(minWidth: 44, minHeight: 44)
                        .accessibilityLabel(Text("Clear the search"))
                }
            }
            .inputBox(focused: searching)
            Flow(spacing: 8) {
                if let item = filter.item {
                    Chip(text: String(localized: "Item: \(itemTitle(item))") + "  ×", on: true) { filter.item = nil }
                }
                agentMenu
                FilterMenu(title: String(localized: "Permission"), chosen: filter.permissions.map(ActivityWords.permissionName)) {
                    ForEach(ActivityWords.permissions, id: \.self) { p in
                        Toggle(ActivityWords.permissionName(p), isOn: binding(p, in: \.permissions))
                    }
                }
                FilterMenu(title: String(localized: "Result"), chosen: filter.outcomes.map(ActivityWords.outcomeName)) {
                    ForEach(ActivityWords.outcomes, id: \.self) { o in
                        Toggle(ActivityWords.outcomeName(o), isOn: binding(o, in: \.outcomes))
                    }
                }
                FilterMenu(title: String(localized: "Period"), chosen: filter.period == .all ? [] : [filter.period.label]) {
                    Picker(String(localized: "Period"), selection: $filter.period) {
                        ForEach(ActivityPeriod.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.inline)
                }
                Chip(text: String(localized: "Only alerts"), on: filter.alertsOnly) { filter.alertsOnly.toggle() }
            }
            if filter.filtering {
                Button("Clear filters") { filter.clear() }
                    .buttonStyle(LinkButtonStyle())
            }
        }
    }

    private var agentMenu: some View {
        let agents = model.agentList.map(\.agent).sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
        let current = filter.agent.map { id in
            agents.first { $0.id == id }.map { AgentText.line($0.name, max: 24) } ?? AgentText.idPrefix(id)
        }
        return FilterMenu(title: String(localized: "Agent"), chosen: current.map { [$0] } ?? []) {
            Button(String(localized: "Every agent")) { filter.agent = nil }
            Divider()
            ForEach(agents, id: \.id) { agent in
                Button(AgentText.line(agent.name, max: 40) + "  " + AgentText.idPrefix(agent.id)) { filter.agent = agent.id }
            }
        }
    }

    private func binding(_ value: String, in set: WritableKeyPath<ActivityFilter, Set<String>>) -> Binding<Bool> {
        Binding(get: { filter[keyPath: set].contains(value) },
                set: { on in if on { filter[keyPath: set].insert(value) } else { filter[keyPath: set].remove(value) } })
    }

    private func itemTitle(_ id: String) -> String {
        lines.first { $0.itemId == id }.flatMap(ActivityWords.title) ?? String(localized: "this one")
    }

    private var empty: some View {
        HStack(alignment: .top, spacing: 16) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 32, height: 80)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(filter.filtering ? "Nothing matches these filters" : "Nothing in the log yet")
                    .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                Text("Every use of an item by an agent, and every decision of yours, is written in the account’s audit log. The server can’t change an event without this iPhone noticing.")
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                if filter.filtering {
                    Button("Clear filters") { filter.clear() }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                        .padding(.top, 6)
                }
            }
        }
    }

    // MARK: Loading

    private func load(debounce: Bool) async {
        guard let service = model.service else { return }
        if debounce {
            try? await Task.sleep(for: .milliseconds(250))
            if Task.isCancelled { return }
        }
        let wanted = filter.input()
        do {
            let found = try await service.run { core, _ in try core.auditLog(filter: wanted) }
            if Task.isCancelled { return }
            lines = found
            status = try? await service.run { core, _ in try core.auditStatus() }
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

/// Events by day, each day a block of lines.
struct ActivityDays: View {
    let lines: [LogEntryInfo]
    var showsItem = true

    var body: some View {
        ForEach(ActivityWords.days(lines), id: \.0) { day, entries in
            SectionLabel(day).padding(.top, 26).padding(.bottom, 10)
            FieldBlock {
                ForEach(Array(entries.enumerated()), id: \.element.seq) { index, entry in
                    if index > 0 { Rule() }
                    ActivityLine(entry: entry, showsItem: showsItem)
                }
            }
        }
    }
}

/// One event on a phone's width: who did what (the agent in cobalt, with
/// the start of its ID), the item and its place, the agent's reason in
/// quotes (T136), then the time, the outcome, the alerts and «Not verified
/// yet» past the last head this iPhone verified.
struct ActivityLine: View {
    let entry: LogEntryInfo
    var showsItem = true

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ActivityWords.sentence(entry, size: 15)
                .fixedSize(horizontal: false, vertical: true)
            if showsItem, let title = ActivityWords.title(entry) {
                Text(verbatim: place(title))
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta.opacity(0.8))
                    .lineLimit(1)
            }
            if let reason = entry.reason, !reason.isEmpty {
                ReasonText(reason: reason)
            }
            Flow(spacing: 6) {
                Text(verbatim: ActivityWords.clock(entry.atMs))
                    .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
                    .monospacedDigit()
                    .frame(minHeight: 20)
                ActivityTags(entry: entry)
            }
            .padding(.top, 2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
    }

    /// «GitHub · Work / Release» when the reference has a place.
    private func place(_ title: String) -> String {
        guard let reference = entry.item, let place = RequestWords.target(reference).where else { return title }
        return "\(title) · \(place)"
    }
}

/// An agent's reason, in quotes and marked «according to the agent»
/// (T136). Cut to `length` characters here, and never by the layout: with
/// no line limit, the marker at the end shows at every text size.
struct ReasonText: View {
    let reason: String

    /// How much of an agent's reason a line shows.
    static let length = 80

    var body: some View {
        Text("\("“\(ActivityWords.shown(reason, max: Self.length))”") (according to the agent)")
            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The outcome, the alerts and «Not verified yet» of an event.
struct ActivityTags: View {
    let entry: LogEntryInfo

    var body: some View {
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
}

/// «Who used it», in an item's detail (ADR 0033 §8.1, §9): what the agents
/// did with this item, newest first, with how each use got through, and
/// «Open in the log». Only the agents' events. Hidden on an account that
/// has no agent and none ever used the item. A log that doesn't check out
/// says so (ADR 0033 §8.4): never «No agent has used it» in its place.
struct WhoUsedIt: View {
    @EnvironmentObject private var model: AppModel
    let itemId: String
    @State private var uses: [ItemUseInfo] = []
    @State private var loaded = false
    @State private var problem: String?
    /// The server couldn't be reached: said as information, not an error.
    @State private var offline = false
    @State private var openLog = false

    /// The newest few: the rest are in Activity.
    static let shown = 5

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let problem {
                SectionLabel("Who used it").padding(.top, 28).padding(.bottom, 10)
                Notice(text: problem, tone: offline ? .info : .error)
            } else if loaded && (!uses.isEmpty || !model.agentList.isEmpty) {
                SectionLabel("Who used it").padding(.top, 28).padding(.bottom, 10)
                if uses.isEmpty {
                    Text("No agent has used it.")
                        .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                } else {
                    FieldBlock {
                        ForEach(Array(uses.prefix(Self.shown).enumerated()), id: \.element.entry.seq) { index, use in
                            if index > 0 { Rule() }
                            UseLine(use: use)
                        }
                    }
                    HStack(spacing: 10) {
                        if uses.count > Self.shown {
                            Text("\(Int64(uses.count - Self.shown)) more")
                                .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                        }
                        Spacer()
                        Button("Open in the log") { openLog = true }
                            .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                            .accessibilityIdentifier("who-used-it-log")
                    }
                    .padding(.top, 10)
                }
            }
        }
        .task(id: "\(itemId)|\(model.generation)") { await load() }
        .sheet(isPresented: $openLog) {
            ActivityView(item: itemId, inSheet: true).environmentObject(model)
        }
    }

    private func load() async {
        // A deleted account's log went with it (ADR 0037 §3): nothing to ask.
        guard let service = model.service, !model.readOnly else { return }
        let id = itemId
        do {
            let activity = try await service.run { core, _ in try core.itemActivity(item: id) }
            if Task.isCancelled { return }
            uses = activity.uses
            problem = nil
            offline = false
        } catch KlavError.Locked {
            model.lock()
        } catch KlavError.Network {
            // Without network, what this item showed stays; with nothing
            // shown yet, say why rather than «No agent has used it».
            if !loaded {
                offline = true
                problem = String(localized: "Who used it shows when this iPhone can reach the server.")
            }
        } catch {
            // A log that doesn't check out (`security`, §8.4) is said, never hidden.
            offline = false
            problem = describe(error)
        }
        loaded = true
    }
}

/// One use: the agent, what it did, its reason, how it got through, when.
private struct UseLine: View {
    let use: ItemUseInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ActivityWords.sentence(use.entry, size: 15)
                .fixedSize(horizontal: false, vertical: true)
            if let reason = use.entry.reason, !reason.isEmpty {
                ReasonText(reason: reason)
            }
            Text(verbatim: [ActivityWords.how(use), ActivityWords.when(use.entry.atMs)]
                .filter { !$0.isEmpty }.joined(separator: " · "))
                .font(.ui(13, relativeTo: .footnote))
                .foregroundStyle(use.how == .denied ? Palette.rojo : Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            let alerts = use.entry.alerts.filter { $0 != "denied" }
            if !alerts.isEmpty {
                Flow(spacing: 6) {
                    ForEach(alerts, id: \.self) { alert in
                        Tag(text: ActivityWords.alert(alert), color: alert == "first_use" ? Palette.tinta : Palette.rojo)
                    }
                }
                .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
    }
}
