import SwiftUI

/// The vault: the list on the left, the item on the right.
struct VaultPane: View {
    @EnvironmentObject private var model: MacModel
    let filter: VaultFilter

    @State private var query = ""
    @State private var items: [ItemInfo] = []
    @State private var projects: [ProjectInfo] = []
    @State private var repoProjectFilter: String?
    @State private var linkingRepo = false
    @State private var problem: String?
    /// How many variables each environment in the list has (ADR 0032 §6).
    @State private var environmentCounts: [String: Int] = [:]
    @FocusState private var searching: Bool
    @FocusState private var listFocused: Bool

    private var projectsById: [String: ProjectInfo] {
        Dictionary(uniqueKeysWithValues: projects.map { ($0.id, $0) })
    }

    private var repoProjects: [ProjectInfo] {
        projects.filter { !$0.repos.isEmpty }
    }

    private var visibleItems: [ItemInfo] {
        guard let repoProjectFilter else { return items }
        return items.filter { $0.projectId == repoProjectFilter }
    }

    private var showsRepoBar: Bool {
        switch filter {
        case .kind(.apiKey), .project: return true
        default: return false
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                searchBar
                if showsRepoBar {
                    repoBar
                }
                Rule()
                list
            }
            .frame(width: 320)
            Rectangle().fill(Palette.linea).frame(width: 1)
            Group {
                if let id = model.selectedItem, let env = items.first(where: { $0.id == id && $0.kind == .environment }) {
                    // An environment has its own page (ADR 0032 §6).
                    EnvironmentDetailView(projectId: env.projectId, name: env.title).id(id)
                } else if let id = model.selectedItem {
                    ItemDetailView(id: id).id(id)
                } else {
                    empty
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .task(id: "\(filter)|\(query)|\(model.generation)") { await load() }
        .onChange(of: filter) { _, _ in repoProjectFilter = nil }
        .sheet(isPresented: $linkingRepo) {
            LinkRepoSheet(projects: projects, initialProjectId: initialLinkProjectId)
                .environmentObject(model)
                .frame(width: 460, height: 380)
        }
    }

    private var initialLinkProjectId: String? {
        if case .project(let id) = filter { return id }
        return repoProjectFilter ?? projects.first?.id
    }

    private var repoBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                if case .project(let id) = filter, let project = projectsById[id] {
                    Text(verbatim: project.displayWithRepo)
                        .font(.ui(12, .medium)).foregroundStyle(Palette.tinta)
                        .lineLimit(1).truncationMode(.middle)
                } else {
                    Text("Repositories")
                        .font(.ui(12, .medium)).foregroundStyle(Palette.gris)
                }
                Spacer(minLength: 6)
                if model.canChangeItems {
                    SmallAction(title: "Link repo…") { linkingRepo = true }
                }
            }
            if case .kind(.apiKey) = filter, !repoProjects.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        Chip(text: String(localized: "All"), on: repoProjectFilter == nil) {
                            repoProjectFilter = nil
                        }
                        ForEach(repoProjects, id: \.id) { project in
                            Chip(text: project.primaryRepoShort ?? project.name,
                                 on: repoProjectFilter == project.id) {
                                repoProjectFilter = repoProjectFilter == project.id ? nil : project.id
                            }
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.bottom, 10)
    }

    private var searchBar: some View {
        HStack(spacing: 8) {
            IconView(icon: .search, size: 14).foregroundStyle(Palette.gris)
            TextField(searchPrompt, text: $query)
                .textFieldStyle(.plain)
                .font(.ui(14))
                .focused($searching)
                .onSubmit { listFocused = true }
            Text(verbatim: "⌘F").font(.ui(11)).foregroundStyle(Palette.gris)
            // Read-only after the deletion (ADR 0037 D-C).
            if model.canChangeItems {
                IconButton(icon: .plus, label: "New item", size: 26) { model.newItem() }
                    .help("New item (⌘N)")
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 52)
        .background {
            Button { searching = true } label: { EmptyView() }
                .keyboardShortcut("f", modifiers: .command)
                .opacity(0)
        }
    }

    private var searchPrompt: String {
        switch filter {
        case .all: return String(localized: "Search your vault")
        case .kind(let kind): return String(localized: "Search \(kind.plural.lowercased())")
        case .vault: return String(localized: "Search this vault")
        case .project: return String(localized: "Search this repository")
        }
    }

    private var list: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 0) {
                    if let problem {
                        Notice(text: problem).padding(14)
                    } else if visibleItems.isEmpty {
                        Text(query.isEmpty ? "Nothing here yet." : "Nothing matches “\(query)”.")
                            .font(.ui(13)).foregroundStyle(Palette.gris)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(16)
                    }
                    ForEach(visibleItems) { item in
                        ItemRow(item: item,
                                repoBadge: rowBadge(for: item),
                                variables: environmentCounts[item.id],
                                selected: model.selectedItem == item.id)
                            .id(item.id)
                            .onTapGesture { model.selectedItem = item.id }
                        Rule().padding(.leading, 58)
                    }
                }
            }
            .focusable()
            .focused($listFocused)
            .focusEffectDisabled()
            .onKeyPress(.downArrow) { move(1, proxy); return .handled }
            .onKeyPress(.upArrow) { move(-1, proxy); return .handled }
        }
    }

    private func rowBadge(for item: ItemInfo) -> String? {
        if let repo = projectsById[item.projectId]?.primaryRepoShort {
            return repo
        }
        if item.kind == .apiKey {
            return "\(item.vault) / \(item.project)"
        }
        return nil
    }

    private var empty: some View {
        VStack(spacing: 14) {
            KeyGlyphShape(square: true)
                .fill(Palette.linea)
                .frame(width: 56, height: 56)
            Text(visibleItems.isEmpty ? "Your vault is empty" : "Pick an item")
                .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
            Text("Copy a password with ⌘C and a user name with ⇧⌘C once it’s open.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
        }
    }

    private func move(_ step: Int, _ proxy: ScrollViewProxy) {
        let shown = visibleItems
        guard !shown.isEmpty else { return }
        let index = shown.firstIndex { $0.id == model.selectedItem } ?? (step > 0 ? -1 : shown.count)
        let next = min(max(index + step, 0), shown.count - 1)
        model.selectedItem = shown[next].id
        proxy.scrollTo(shown[next].id)
    }

    private func load() async {
        let text = query.trimmingCharacters(in: .whitespaces)
        if !text.isEmpty { try? await Task.sleep(for: .milliseconds(120)) }
        guard !Task.isCancelled else { return }
        var q = ItemQuery(vaultId: nil, projectId: nil, text: text.isEmpty ? nil : text, kind: nil, trash: false)
        switch filter {
        case .all: break
        case .kind(let kind): q.kind = kind
        case .vault(let id): q.vaultId = id
        case .project(let id): q.projectId = id
        }
        let query = q
        do {
            async let loadedItems = model.run { try $0.items(query: query) }
            async let loadedProjects = model.run { try $0.projects(vaultId: nil) }
            items = try await loadedItems
            projects = (try? await loadedProjects) ?? []
            if items.contains(where: { $0.kind == .environment }) {
                let listed = (try? await model.run { try $0.environments(projectId: nil) }) ?? []
                environmentCounts = Dictionary(listed.map { ($0.id, Int($0.variables)) }, uniquingKeysWith: { a, _ in a })
            }
            problem = nil
            if let selected = model.selectedItem, !visibleItems.contains(where: { $0.id == selected }) {
                model.selectedItem = visibleItems.first?.id
            } else if model.selectedItem == nil {
                model.selectedItem = visibleItems.first?.id
            }
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }
}

/// Sheet to link or unlink Git repositories on a project (ADR 0032 §2).
private struct LinkRepoSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let projects: [ProjectInfo]
    let initialProjectId: String?

    @State private var selectedProjectId = ""
    @State private var repoInput = ""
    @State private var repos: [String] = []
    @State private var busy = false
    @State private var problem: String?

    private var selectedProject: ProjectInfo? {
        projects.first { $0.id == selectedProjectId }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Title("Link a repository", size: 20)
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            }
            .padding(.horizontal, 22)
            .frame(height: 56)
            .overlay(alignment: .bottom) { Rule() }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Link a Git repository to a project so Klav groups its API keys and helps agents find the right project automatically.")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)

                    VStack(alignment: .leading, spacing: 6) {
                        FieldLabel("Project")
                        Picker(String(localized: "Project"), selection: $selectedProjectId) {
                            ForEach(projects, id: \.id) { project in
                                Text(project.displayWithRepo).tag(project.id)
                            }
                        }
                        .labelsHidden()
                        .onChange(of: selectedProjectId) { _, _ in syncSelected() }
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        FieldLabel("Repository URL")
                        HStack(spacing: 8) {
                            TextField(String(localized: "github.com/owner/repo or git@github.com:owner/repo.git"), text: $repoInput)
                                .textFieldStyle(.plain)
                                .font(.ui(13)).foregroundStyle(Palette.tinta)
                                .padding(.horizontal, 10).padding(.vertical, 8)
                                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                                .onSubmit { Task { await addRepo() } }
                            Button(busy ? String(localized: "Saving…") : String(localized: "Link")) {
                                Task { await addRepo() }
                            }
                            .buttonStyle(PrimaryButtonStyle(compact: true))
                            .fixedSize()
                            .disabled(busy || repoInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || selectedProject == nil)
                        }
                    }

                    if !repos.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            FieldLabel("Linked repositories")
                            FieldBlock {
                                ForEach(Array(repos.enumerated()), id: \.element) { idx, repo in
                                    if idx > 0 { Rule() }
                                    HStack {
                                        Text(verbatim: repo).font(.mono(12)).foregroundStyle(Palette.tinta)
                                        Spacer()
                                        SmallAction(title: "Remove") { Task { await removeRepo(repo) } }
                                    }
                                    .padding(.horizontal, 12).padding(.vertical, 8)
                                }
                            }
                        }
                    }

                    if let problem { Notice(text: problem) }
                }
                .padding(22)
            }
        }
        .background(Palette.papel)
        .onAppear {
            selectedProjectId = initialProjectId ?? projects.first?.id ?? ""
            syncSelected()
        }
    }

    private func syncSelected() {
        repos = selectedProject?.repos ?? []
        problem = nil
    }

    private func addRepo() async {
        guard let project = selectedProject else { return }
        let raw = repoInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }
        busy = true
        problem = nil
        do {
            let updated = try await model.setProjectRepos(vaultId: project.vaultId, projectId: project.id,
                                                          repos: repos + [raw])
            repos = updated.repos
            repoInput = ""
        } catch {
            problem = describe(error)
        }
        busy = false
    }

    private func removeRepo(_ repo: String) async {
        guard let project = selectedProject else { return }
        busy = true
        problem = nil
        do {
            let next = repos.filter { $0 != repo }
            let updated = try await model.setProjectRepos(vaultId: project.vaultId, projectId: project.id,
                                                          repos: next)
            repos = updated.repos
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}

/// A row: the site's tile, the title, the user name, and the live code of
/// an item with one (docs/diseno-visual §4.1).
private struct ItemRow: View {
    @EnvironmentObject private var model: MacModel
    let item: ItemInfo
    let repoBadge: String?
    var variables: Int?
    let selected: Bool
    @State private var noCode = false

    var body: some View {
        HStack(spacing: 12) {
            Tile(title: item.title, site: item.urls.first, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: item.title)
                    .font(.ui(13, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                Text(verbatim: subtitle)
                    .font(.ui(12)).foregroundStyle(Palette.gris).lineLimit(1)
            }
            Spacer(minLength: 6)
            if !item.protectedBy.isEmpty {
                IconView(icon: .lock, size: 13).foregroundStyle(Palette.tinta)
                    .help(EnvironmentWords.protectedBy(item.protectedBy))
                    .accessibilityLabel(Text("Protected"))
            }
            // With the presence gate on, a code may ask for Touch ID: rows
            // fetch none on their own (ADR 0041), the item shows it on demand.
            if (item.kind == .totp || item.kind == .login) && !noCode && model.info?.presenceGate != true {
                LiveCode(id: item.id, title: item.title, style: .row,
                         fetch: fetchCode, onNone: { noCode = true })
                    .scaleEffect(0.82, anchor: .trailing)
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 54)
        .background(selected ? Palette.niebla : Palette.papel)
        .overlay(alignment: .leading) {
            if selected { Rectangle().fill(Palette.tinta).frame(width: 2) }
        }
        .contentShape(Rectangle())
    }

    private var subtitle: String {
        if item.kind == .environment {
            return EnvironmentWords.row(vault: item.vault, project: item.project, variables: variables)
        }
        if let username = item.username, !username.isEmpty {
            return username
        }
        if let repoBadge {
            return repoBadge
        }
        return item.kind.shortName
    }

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let engine = model.engine
        return { id in try await Task.detached { try engine.totp(id: id) }.value }
    }
}

/// One item: its fields in a block with cross corners, secrets as noise
/// until shown, the live code, its sites, the `klav://` reference and the
/// notes.
struct ItemDetailView: View {
    @EnvironmentObject private var model: MacModel
    let id: String

    @State private var detail: ItemDetail?
    @State private var revealed: [String: String] = [:]
    @State private var notes: String?
    @State private var previous: [PreviousPasswordInfo] = []
    @State private var problem: String?
    /// Confirming or removing the sites an agent added.
    @State private var settlingSites = false

    var body: some View {
        ScrollView {
            if let detail {
                content(detail)
                    .padding(.horizontal, 36)
                    .padding(.vertical, 30)
                    .frame(maxWidth: 680, alignment: .leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if let problem {
                Notice(text: problem).padding(30)
            }
        }
        .task(id: model.generation) { await load() }
        .onChange(of: model.phase) { _, phase in if phase != .unlocked { hideAll() } }
        .onDisappear { hideAll() }
        // Opening the editor, or coming back from it, hides what was shown.
        .onChange(of: model.editor) { _, _ in hideAll() }
    }

    @ViewBuilder
    private func content(_ detail: ItemDetail) -> some View {
        let info = detail.info
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                Tile(title: info.title, site: info.confirmedUrls.first, size: 44)
                VStack(alignment: .leading, spacing: 4) {
                    Title(info.title, size: 26)
                    Text(verbatim: "\(info.kind.shortName) · \(info.vault) / \(info.project)")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                }
                Spacer(minLength: 12)
                // Read-only after the deletion (ADR 0037 D-C).
                if model.canChangeItems {
                    Button("Edit") { model.editor = .edit(info.id) }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                        .help("Edit (⌘E)")
                }
            }
            if let problem { Notice(text: problem).padding(.top, 14) }
            // Protected by a reference from a protected environment (ADR
            // 0032 §3.1): klavd asks for Touch ID on every Show and Copy.
            if !info.protectedBy.isEmpty {
                ProtectedNotice(text: EnvironmentWords.protectedBy(info.protectedBy)).padding(.top, 14)
            }

            // Sites get their own rows below, with «Open».
            let shown = detail.fields.filter { $0.filled && $0.kind != .totp && $0.kind != .file && $0.kind != .url }
            VStack(spacing: 0) {
                ForEach(Array(shown.enumerated()), id: \.element.name) { index, field in
                    if index > 0 { Rule() }
                    fieldRow(field)
                }
                if detail.hasTotp {
                    if !shown.isEmpty { Rule() }
                    LiveCode(id: id, title: info.title, style: .detail, fetch: fetchCode,
                             onError: { error in
                                 if !(error is CancellationError) { problem = describe(error) }
                             },
                             onCopy: { model.copy($0) },
                             onDemand: model.info?.presenceGate == true)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                // Only the sites the person confirmed: the ones an agent
                // added go below, apart (ADR 0030 §7).
                ForEach(Array(info.confirmedUrls.enumerated()), id: \.offset) { _, url in
                    Rule()
                    row(label: "Website") {
                        Text(verbatim: url).font(.ui(14)).foregroundStyle(Palette.tinta).textSelection(.enabled)
                    } actions: {
                        if let link = URL(string: url.contains("://") ? url : "https://\(url)") {
                            SmallAction(title: "Open") { NSWorkspace.shared.open(link) }
                        }
                    }
                }
                Rule()
                row(label: "Reference for agents") {
                    Text(verbatim: info.reference).font(.mono(12)).foregroundStyle(Palette.gris)
                        .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                } actions: {
                    IconButton(icon: .copy, label: "Copy the reference for agents", size: 26) {
                        model.copy(info.reference)
                    }
                }
            }
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
            .padding(.top, 24)

            if !info.pendingUrls.isEmpty { agentSites(info) }

            if detail.hasNotes {
                SectionLabel("Notes").padding(.top, 28).padding(.bottom, 10)
                if let notes {
                    Text(verbatim: notes).font(.ui(14)).foregroundStyle(Palette.tinta)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                } else {
                    Button("Show notes") { Task { await showNotes() } }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                }
            }

            if !previous.isEmpty {
                SectionLabel("Previous passwords").padding(.top, 28).padding(.bottom, 10)
                VStack(spacing: 0) {
                    ForEach(Array(previous.enumerated()), id: \.element.index) { index, entry in
                        if index > 0 { Rule() }
                        row(label: LocalizedStringKey(previousLabel(entry))) {
                            MaskedValue(value: nil)
                        } actions: {
                            IconButton(icon: .copy, label: "Copy", size: 26) { Task { await copyPrevious(entry) } }
                        }
                    }
                }
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            }

            // After the deletion the log is gone with the account (D-C).
            if !model.accountDeleted { WhoUsedIt(itemId: id) }

            Text(verbatim: "Updated \(Date(timeIntervalSince1970: Double(info.updatedAt) / 1000).formatted(date: .abbreviated, time: .shortened)) · version \(info.version)")
                .font(.ui(12)).foregroundStyle(Palette.gris)
                .padding(.top, 24)

            if model.canChangeItems {
                Button("Move to the trash…") { model.trashing = info }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .padding(.top, 12)
            }
        }
        .background {
            // Copy shortcuts of the open item.
            Group {
                Button("") { Task { await copyField(named: "password") } }
                    .keyboardShortcut("c", modifiers: .command)
                Button("") { Task { await copyField(named: "username") } }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
            }
            .opacity(0)
        }
    }

    /// Sites an agent added (ADR 0030 §7): never filled until the person
    /// confirms them. As in `klav item sites`, the extension and the
    /// iPhone, Confirm and Remove act on all of them.
    @ViewBuilder
    private func agentSites(_ info: ItemInfo) -> some View {
        let agent = info.authorAgentId.flatMap { model.knownAgents[$0]?.name }
        Group {
            if let agent {
                SectionLabel(String(localized: "Sites added by \(agent)"))
            } else {
                SectionLabel("Sites added by an agent")
            }
        }
        .padding(.top, 28)
        .padding(.bottom, 10)
        VStack(spacing: 0) {
            ForEach(Array(info.pendingUrls.enumerated()), id: \.offset) { index, url in
                if index > 0 { Rule() }
                row(label: "Not confirmed") {
                    // The whole URL: a look-alike must be readable.
                    Text(verbatim: url).font(.ui(14)).foregroundStyle(Palette.tinta)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                } actions: {
                    EmptyView()
                }
            }
        }
        .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
        Text("Klav doesn’t fill them until you confirm them. Confirm only sites you know are this login’s.")
            .font(.ui(12.5)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 10)
        if model.canChangeItems {
            HStack(spacing: 8) {
                Button("Confirm") { Task { await settleSites(info, remove: false) } }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .accessibilityLabel(Text("Confirm the sites the agent added"))
                Button("Remove") { Task { await settleSites(info, remove: true) } }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .accessibilityLabel(Text("Remove the sites the agent added"))
            }
            .disabled(settlingSites)
            .padding(.top, 10)
        }
    }

    private func settleSites(_ info: ItemInfo, remove: Bool) async {
        settlingSites = true
        defer { settlingSites = false }
        problem = nil
        do {
            try await model.settleSites(info, remove: remove)
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    private func fieldRow(_ field: FieldInfo) -> some View {
        // The iPhone's name for a known field, in the interface's language.
        row(label: LocalizedStringKey(field.displayName)) {
            if field.secret {
                MaskedValue(value: revealed[field.name])
            } else {
                Text(verbatim: field.value ?? "").font(.ui(14)).foregroundStyle(Palette.tinta)
                    .textSelection(.enabled)
            }
        } actions: {
            if field.secret {
                SmallAction(title: revealed[field.name] == nil ? "Show" : "Hide") {
                    Task { await toggle(field) }
                }
            }
            IconButton(icon: .copy, label: "Copy", size: 26) { Task { await copy(field) } }
                .help(field.kind == .password ? "Copy (⌘C)" : field.kind == .username ? "Copy (⇧⌘C)" : "Copy")
        }
    }

    private func row<Value: View, Actions: View>(label: LocalizedStringKey,
                                                 @ViewBuilder value: () -> Value,
                                                 @ViewBuilder actions: () -> Actions) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.ui(12)).foregroundStyle(Palette.gris)
                value()
            }
            Spacer(minLength: 8)
            HStack(spacing: 6) { actions() }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let model = model
        return { id in
            try await model.value({ try $0.totp(id: id) },
                                  withPassword: { try $0.totpWithPassword(id: id, password: $1) })
        }
    }

    private func previousLabel(_ entry: PreviousPasswordInfo) -> String {
        let until = Date(timeIntervalSince1970: Double(entry.toMs) / 1000).formatted(date: .abbreviated, time: .omitted)
        return entry.unconfirmed
            ? String(localized: "Generated, not confirmed · \(until)")
            : String(localized: "Until \(until)")
    }

    // MARK: Loading and values

    private func load() async {
        let id = id
        do {
            detail = try await model.run { try $0.item(id: id) }
            #if DEBUG
            if let detail, Snapshot.takeTrashSheet() { model.trashing = detail.info }
            #endif
            previous = (try? await model.run { try $0.passwordHistory(id: id) })?.entries ?? []
            problem = nil
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    private func value(_ name: String) async -> String? {
        let id = id
        do {
            return try await model.value({ try $0.fieldValue(id: id, field: name) },
                                         withPassword: { try $0.fieldValueWithPassword(id: id, field: name, password: $1) })
        } catch is CancellationError {
            return nil
        } catch {
            problem = describe(error)
            return nil
        }
    }

    private func toggle(_ field: FieldInfo) async {
        if revealed[field.name] != nil {
            revealed[field.name] = nil
        } else if let value = await value(field.name) {
            revealed[field.name] = value
        }
    }

    private func copy(_ field: FieldInfo) async {
        if field.secret || field.value == nil {
            if let value = await value(field.name) { model.copy(value) }
        } else if let value = field.value {
            model.copy(value)
        }
    }

    private func copyField(named name: String) async {
        guard let field = detail?.fields.first(where: { $0.name == name || $0.kind == (name == "password" ? .password : .username) })
        else { return }
        await copy(field)
    }

    private func showNotes() async {
        let id = id
        do {
            notes = try await model.value({ try $0.notes(id: id) },
                                          withPassword: { try $0.notesWithPassword(id: id, password: $1) }) ?? ""
        } catch is CancellationError {
        } catch {
            problem = describe(error)
        }
    }

    private func copyPrevious(_ entry: PreviousPasswordInfo) async {
        let id = id, index = entry.index
        do {
            let value = try await model.value(
                { try $0.previousPassword(id: id, index: index) },
                withPassword: { try $0.previousPasswordWithPassword(id: id, index: index, password: $1) })
            model.copy(value)
        } catch is CancellationError {
        } catch {
            problem = describe(error)
        }
    }

    private func hideAll() {
        revealed = [:]
        notes = nil
    }
}
