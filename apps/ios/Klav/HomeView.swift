import SwiftUI

/// Items of one project, under its "Vault / Project" label.
struct ItemGroup: Identifiable {
    let id: String
    let vault: String
    let project: String
    var items: [ItemInfo]

    static func grouping(_ items: [ItemInfo]) -> [ItemGroup] {
        var groups: [ItemGroup] = []
        for item in items.sorted(by: { ($0.vault, $0.project, $0.title.lowercased()) < ($1.vault, $1.project, $1.title.lowercased()) }) {
            if groups.last?.id == item.projectId {
                groups[groups.count - 1].items.append(item)
            } else {
                groups.append(ItemGroup(id: item.projectId, vault: item.vault, project: item.project, items: [item]))
            }
        }
        return groups
    }
}

/// The open vault: agents' requests on top, search, the type tabs, then
/// every item grouped by where it lives. Logins with a one-time code show
/// it live; «Codes» lists only those, with the code large.
struct HomeView: View {
    @EnvironmentObject private var model: AppModel

    @State private var search = ""
    /// What the search found, of every type: the tabs count it.
    @State private var listed: [ItemInfo] = []
    @State private var filter: VaultFilter = .all
    /// The items with a code (klav-core's `items` with `codes`), asked once
    /// the vault shows and again when it changes. Nil: not known yet.
    @State private var codeIds: Set<String>?
    @State private var loaded = false
    @State private var problem: String?
    @State private var settings = false
    @State private var creating = false
    @State private var importing = false
    @State private var reviewing: AgentItem?
    @State private var agents = false
    @State private var highlighted: String?
    @FocusState private var searching: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                bar
                // ADR 0037 §7.6, D-C: fixed above the vault, which stays
                // readable.
                if model.readOnly { DeletedNotice() }
                ScrollViewReader { scroller in
                    ScrollView {
                        // The requests stay out of the lazy stack: a task card
                        // can be taller than the screen, and a lazy child that
                        // changes height while scrolled through sends the
                        // stack into a layout loop at accessibility sizes.
                        VStack(alignment: .leading, spacing: 0) {
                            // ADR 0037 §7.4: above the vault while pending.
                            DeletionBanner()
                            if model.readOnly { DeletedAccountCard() }
                            // Every agent paused: never out of sight (ADR 0033 §7.5).
                            if let pause = model.everyonePaused {
                                PausedCard(pause: pause) { agents = true }.padding(.top, 16)
                            }
                            if !model.readOnly {
                                RequestsSection(highlighted: highlighted) { reviewing = $0 }
                            }
                            LazyVStack(alignment: .leading, spacing: 0) {
                                searchField
                                let tabs = VaultFilter.tabs(listed, codes: codeCount, chosen: filter)
                                if !tabs.isEmpty {
                                    VaultTabs(tabs: tabs, chosen: $filter).padding(.top, 12)
                                }
                                if let offline = model.offline {
                                    Notice(text: offline, tone: .info).padding(.top, 12)
                                }
                                if let passkeys = model.passkeyNotice {
                                    Notice(text: passkeys).padding(.top, 12)
                                        .task(id: model.passkeyNoticeID) { await model.passkeyNoticeShown() }
                                }
                                if let problem {
                                    Notice(text: problem).padding(.top, 12)
                                }
                                let shown = filter.filtered(listed, codeIds: codeIds)
                                if loaded && shown.isEmpty && (filter != .codes || codeIds != nil) {
                                    empty
                                }
                                if filter == .codes {
                                    // Each row has its copy square and says so to VoiceOver.
                                    Spacer().frame(height: 8)
                                    ForEach(shown.sorted { $0.title.lowercased() < $1.title.lowercased() }, id: \.id) { item in
                                        CodeRow(item: item)
                                        Rule()
                                    }
                                } else {
                                    ForEach(ItemGroup.grouping(shown)) { group in
                                        SectionLabel(group.vault + " / " + group.project)
                                            .padding(.top, 22)
                                            .padding(.bottom, 4)
                                        ForEach(group.items, id: \.id) { item in
                                            ItemRow(item: item)
                                        }
                                    }
                                }
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 32)
                    }
                    .scrollDismissesKeyboard(.immediately)
                    .refreshable {
                        await model.sync(force: true)
                        await model.loadRequests()
                    }
                    .onChange(of: model.route) { _, _ in follow(scroller) }
                    .onChange(of: model.approvals) { _, _ in follow(scroller) }
                    .onChange(of: model.registrations) { _, _ in follow(scroller) }
                    .onChange(of: model.tasks) { _, _ in follow(scroller) }
                    .onAppear { follow(scroller) }
                }
            }
            .background(Palette.papel)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: String.self) { id in ItemView(id: id) }
        }
        .task(id: "\(model.generation)|\(search)") { await load() }
        .task(id: model.generation) { await loadCodes() }
        // ADR 0025 §2: after AutoFill filled a login saved for a subdomain.
        .alert(
            model.siteOffer.map { Text("Add \($0.host) to \($0.title)?") } ?? Text(""),
            isPresented: Binding(get: { model.siteOffer != nil && !model.covered },
                                 set: { if !$0, model.siteOffer != nil { model.dismissSiteOffer() } }),
            presenting: model.siteOffer
        ) { offer in
            Button("Add this site") { Task { await model.addSite(offer) } }
            Button("Not now", role: .cancel) { model.dismissSiteOffer() }
        } message: { offer in
            Text("It’s saved for \(offer.savedFor). Klav filled it on \(offer.host); with this site added, it’s offered there first.")
        }
        // Without APNs (or with notifications off) the requests still show up.
        .task(id: model.inForeground) {
            while model.inForeground, !Task.isCancelled {
                await model.loadRequests()
                try? await Task.sleep(for: .seconds(8))
            }
        }
        .sheet(item: $reviewing) { agent in
            AgentReviewView<AppModel>(agent: agent).environmentObject(model)
        }
        .sheet(isPresented: $importing) {
            ImportView().environmentObject(model)
        }
        .sheet(isPresented: $creating) {
            ItemEditor(mode: .create) { _ in model.changed() }.environmentObject(model)
        }
        .sheet(isPresented: $agents) {
            AgentsView().environmentObject(model)
        }
        .sheet(isPresented: $settings) {
            SettingsView().environmentObject(model).environmentObject(model.preferences)
        }
    }

    private var bar: some View {
        HStack(spacing: 8) {
            Wordmark()
            Spacer(minLength: 8)
            // Read-only after the deletion: nothing to add, no agents left.
            if !model.readOnly {
                IconButton(icon: .plus, label: "New item") { creating = true }
                IconButton(icon: .robot, label: "Agents") { agents = true }
                    .accessibilityIdentifier("home-agents")
            }
            IconButton(icon: .gear, label: "Settings") { settings = true }
            Button("Lock") { model.lock(byHand: true) }
                .buttonStyle(SecondaryButtonStyle(compact: true))
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 56)
        .overlay(alignment: .bottom) { Rule() }
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            IconView(icon: .search).foregroundStyle(Palette.gris)
            TextField("Search your vault", text: $search, prompt: placeholder("Search your vault"))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($searching)
                .submitLabel(.search)
            if !search.isEmpty {
                Button {
                    search = ""
                } label: {
                    IconView(icon: .close).foregroundStyle(Palette.gris).frame(width: 32, height: 32)
                }
                .accessibilityLabel("Clear the search")
            }
        }
        .inputBox(focused: searching)
        .padding(.top, 16)
    }

    /// How many of the items found have a code; nil until klav-core said.
    private var codeCount: Int? {
        codeIds.map { ids in listed.filter { ids.contains($0.id) }.count }
    }

    private var empty: some View {
        VStack(alignment: .leading, spacing: 6) {
            emptyTitle
                .font(.ui(16, .medium))
                .foregroundStyle(Palette.tinta)
            emptyText
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
            if search.isEmpty && (filter == .all || filter == .codes) {
                Button("Import from another app") { importing = true }
                    .buttonStyle(LinkButtonStyle())
                    .accessibilityIdentifier("home-import")
            }
        }
        .padding(.top, 24)
    }

    private var emptyTitle: Text {
        switch (filter, search.isEmpty) {
        case (.all, true): return Text("Your vault is empty.")
        case (.all, false): return Text("Nothing matches “\(search)”.")
        case (.codes, true): return Text("No one-time codes yet.")
        case (_, true): return Text("Nothing in \(filter.label).", comment: "An empty type tab; the type")
        case (_, false): return Text("Nothing in \(filter.label) matches “\(search)”.", comment: "A type tab the search left empty; the type, the search")
        }
    }

    private var emptyText: Text {
        switch (filter, search.isEmpty) {
        case (.all, true): return Text("Save the first one with +, or from the terminal or the browser.")
        case (.codes, true): return Text("Add one to a login, or bring yours from Google Authenticator.")
        case (_, true): return Text("Save the first one with +, or from the terminal or the browser.")
        case (_, false): return Text("Search by title, user name, site or tag.")
        }
    }

    /// Which items have a code: to count «Codes» and to list it.
    private func loadCodes() async {
        guard let service = model.service else { return }
        do {
            let items = try await service.run { core, _ in try core.items(query: ItemQuery(codes: true)) }
            codeIds = Set(items.map(\.id))
        } catch KlavError.Locked {
            model.lock()
        } catch {
            // The tabs simply go without «Codes»; the list itself says what failed.
            codeIds = codeIds ?? []
        }
    }

    /// A notification was opened: bring its request into view.
    private func follow(_ scroller: ScrollViewProxy) {
        guard let route = model.route else { return }
        switch route {
        case .agent(let id):
            guard let agent = model.registrations.first(where: { $0.id == id }) else { return }
            model.route = nil
            reviewing = agent
        case .approval(let id):
            guard model.approvals.contains(where: { $0.id == id }) else { return }
            model.route = nil
            highlighted = id
            withAnimation { scroller.scrollTo(id, anchor: .top) }
        case .task(let id):
            guard model.tasks.contains(where: { $0.id == id }) else { return }
            model.route = nil
            highlighted = id
            withAnimation { scroller.scrollTo(id, anchor: .top) }
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        let text = search.trimmingCharacters(in: .whitespaces)
        if !text.isEmpty {
            // Wait for the typing to settle.
            try? await Task.sleep(for: .milliseconds(150))
            if Task.isCancelled { return }
        } else {
            // The vault changed: an item may have gained a code.
            CodeMemo.none = []
        }
        do {
            let items = try await service.run { core, _ in
                try core.items(query: ItemQuery(text: text.isEmpty ? nil : text))
            }
            listed = items
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

/// One item in the list: its site's logo or initial, title and user, and at the end its
/// live one-time code (tap to copy) or its kind in Geist Mono.
struct ItemRow: View {
    let item: ItemInfo
    @EnvironmentObject private var model: AppModel
    @State private var noCode = false
    @Environment(\.dynamicTypeSize) private var typeSize

    private var showsCode: Bool {
        item.kind.mayHaveCode && !noCode && !CodeMemo.none.contains(item.id) && model.inForeground
    }

    var body: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(alignment: .center, spacing: 12))
        layout {
            NavigationLink(value: item.id) {
                HStack(spacing: 12) {
                Tile(title: item.title, site: item.confirmedUrls.first)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(.ui(16, .medium))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(typeSize.isAccessibilitySize ? 2 : 1)
                    if let sub = item.listSubtitle {
                        Text(sub)
                            .font(.ui(14, relativeTo: .subheadline))
                            .foregroundStyle(Palette.gris)
                            .lineLimit(1)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 60)
                .contentShape(Rectangle())
            }
            .buttonStyle(RowButtonStyle())
            if showsCode {
                LiveCode(id: item.id, title: item.title, style: .row,
                         fetch: fetchCode,
                         onNone: { noCode = true },
                         onError: { error in if case KlavError.Locked = error { model.lock() } },
                         onCopy: { model.copy($0) })
                    // Under the title, past the tile, when the row stacks.
                    .padding(.leading, typeSize.isAccessibilitySize ? 46 : 0)
            } else if !typeSize.isAccessibilitySize {
                // The kind is a hint; with large text it would read as another row.
                Text(item.kind.tag)
                    .font(.mono(12))
                    .foregroundStyle(Palette.gris)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let service = model.service
        return { id in
            guard let service else { throw CancellationError() }
            return try await service.run { core, _ in try core.totp(id: id) }
        }
    }
}

/// A list row: mist and a cobalt rule on the left while pressed, like the
/// extension's chosen row.
struct RowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 8)
            .background(configuration.isPressed ? Palette.niebla : Color.clear)
            .overlay(alignment: .leading) {
                Rectangle().fill(configuration.isPressed ? Palette.cobalto : Color.clear).frame(width: 2)
            }
            .padding(.horizontal, -8)
    }
}
