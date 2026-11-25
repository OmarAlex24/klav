import SwiftUI

/// Creates an item (⌘N) or edits one (⌘E), as the iPhone's editor does:
/// the same kinds and fields (`ItemDraft`), the generator for a login's
/// password, a one-time code from a key or an `otpauth://` link, and a
/// title the project doesn't have yet. Secret values are never pre-filled:
/// an empty secret field keeps what the item has. Whatever the person typed
/// lives only in this sheet, and goes with it: on Cancel, on save, and when
/// Klav locks (`MacModel.editor` is cleared).
struct ItemEditorSheet: View {
    @EnvironmentObject private var model: MacModel
    let request: EditorRequest

    @State private var detail: ItemDetail?
    @State private var kind: Kind = .login
    @State private var projects: [ProjectInfo] = []
    @State private var projectId: String?
    /// The project's items, for a title that is already taken.
    @State private var siblings: [ItemInfo] = []
    @State private var title = ""
    @State private var values: [String: String] = [:]
    @State private var visible: Set<String> = []
    @State private var url = ""
    @State private var notes = ""
    @State private var originalNotes: String?
    @State private var busy = false
    @State private var problem: String?
    @State private var prepared = false
    /// The field the generator is open for.
    @State private var generatingFor: String?
    @FocusState private var focus: String?

    private var editing: Bool { if case .edit = request { return true }; return false }

    /// The site the generator follows: the URL being typed, or the item's
    /// first confirmed one.
    private var generatorSite: String? {
        let typed = url.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { return typed }
        return detail?.info.confirmedUrls.first
    }

    private var fields: [FieldSpec] {
        if let detail { return ItemDraft.editFields(detail) }
        return editing ? [] : ItemDraft.templateFields(kind)
    }

    private var isLogin: Bool { detail.map { $0.info.kind == .login } ?? (!editing && kind == .login) }

    /// Another item of the project already has this title (klav-client
    /// refuses it too; this says so before saving, in the person's words).
    private var taken: Bool {
        let project = detail?.info.projectId ?? projectId
        let others = siblings.filter { $0.id != detail?.info.id }
        if let detail, title.trimmingCharacters(in: .whitespaces) == detail.info.title { return false }
        return titleTaken(title, in: project, items: others)
    }

    private var canSave: Bool {
        !busy && !title.trimmingCharacters(in: .whitespaces).isEmpty && !taken && (!editing || detail != nil)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Title(editing ? "Edit" : "New item", size: 22)
                if let detail {
                    Text(verbatim: "\(detail.info.vault) / \(detail.info.project)")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                }
                Spacer()
            }
            .padding(.horizontal, 24)
            .frame(height: 60)
            .overlay(alignment: .bottom) { Rule() }

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if !editing {
                        kindPicker
                        labelled("Where") { projectPicker }
                    }
                    labelled("Title") {
                        TextField("", text: $title, prompt: placeholder("GitHub, Bank, Test server…", font: .ui(14)))
                            .textFieldStyle(.plain)
                            .focused($focus, equals: "title")
                            .inputBox(focused: focus == "title", font: .ui(14))
                        if taken {
                            Notice(text: String(localized: "There’s already an item called “\(title.trimmingCharacters(in: .whitespaces))” there. Choose another title."))
                                .padding(.top, 6)
                        }
                    }
                    ForEach(fields) { field in
                        labelled(field.label) { input(field) }
                    }
                    if isLogin {
                        labelled(editing ? "Add a site" : "Site") {
                            TextField("", text: $url, prompt: placeholder(String("https://github.com"), font: .ui(14)))
                                .textFieldStyle(.plain)
                                .focused($focus, equals: "url")
                                .inputBox(focused: focus == "url", font: .ui(14))
                        }
                    }
                    labelled("Notes") { notesInput }

                    if let pending = detail?.info.pendingUrls, !pending.isEmpty {
                        // Any version the person saves is theirs: all its
                        // sites count from then on (ADR 0030 §7).
                        Notice(text: String(localized: "Saving also confirms the sites an agent added: \(pending.joined(separator: ", ")). To drop them, use Remove on the item instead."),
                               tone: .info)
                    }
                    if let problem { Notice(text: problem) }
                }
                .padding(24)
            }

            HStack(spacing: 8) {
                Spacer()
                Button("Cancel") { model.editor = nil }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button(busy ? "Saving…" : (editing ? "Save the changes" : "Save to the vault")) { save() }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
            .padding(.horizontal, 24)
            .frame(height: 60)
            .overlay(alignment: .top) { Rule() }
        }
        .frame(width: 560, height: 640)
        .background(Palette.papel)
        .sheet(isPresented: Binding(get: { generatingFor != nil }, set: { if !$0 { generatingFor = nil } })) {
            GeneratorSheet(site: generatorSite) { password in
                if let name = generatingFor {
                    values[name] = password
                    visible.insert(name)
                }
            }
            .environmentObject(model)
        }
        .task { await prepare() }
        .onChange(of: projectId) { _, _ in Task { await loadSiblings() } }
        // Hidden again whenever the app goes to the background, like the
        // item's own fields.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            visible = []
        }
        .onDisappear(perform: forget)
    }

    // MARK: Pieces

    /// The kind as square segments; the chosen one in ink.
    private var kindPicker: some View {
        HStack(spacing: -1) {
            ForEach(ItemDraft.creatable, id: \.self) { option in
                Button {
                    kind = option
                    values = [:]
                    visible = []
                } label: {
                    HStack(spacing: 6) {
                        IconView(icon: option.icon, size: 16)
                        Text(ItemDraft.shortLabel(option)).lineLimit(1)
                    }
                    .font(.ui(13, kind == option ? .medium : .regular))
                    .foregroundStyle(kind == option ? Palette.botonTexto : Palette.tinta)
                    .frame(maxWidth: .infinity, minHeight: 34)
                    .background(kind == option ? Palette.boton : Palette.papel)
                    .overlay(Rectangle().strokeBorder(kind == option ? Palette.boton : Palette.linea, lineWidth: 1))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(kind == option ? .isSelected : [])
            }
        }
    }

    private var projectPicker: some View {
        Menu {
            ForEach(projects, id: \.id) { project in
                Button(project.displayWithRepo) { projectId = project.id }
            }
        } label: {
            HStack {
                Text(projects.first { $0.id == projectId }?.displayWithRepo ?? String(localized: "Choose a project"))
                    .font(.ui(14)).foregroundStyle(Palette.tinta)
                Spacer()
                Text(verbatim: "▾").font(.ui(10)).foregroundStyle(Palette.gris).accessibilityHidden(true)
            }
            .padding(.horizontal, 12)
            .frame(minHeight: 40)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .accessibilityLabel("Where to save it")
    }

    @ViewBuilder
    private func input(_ field: FieldSpec) -> some View {
        let binding = Binding(get: { values[field.name] ?? "" }, set: { values[field.name] = $0 })
        let shown = visible.contains(field.name)
        HStack(spacing: 8) {
            Group {
                if field.secret && !shown {
                    SecureField("", text: binding, prompt: placeholder(field.placeholder, font: .ui(14)))
                } else {
                    TextField("", text: binding, prompt: placeholder(field.placeholder, font: .ui(14)))
                }
            }
            .textFieldStyle(.plain)
            .focused($focus, equals: field.name)
            .inputBox(focused: focus == field.name, font: field.secret ? .mono(13) : .ui(14))
            .accessibilityLabel(field.label)
            if field.secret {
                Button(shown ? "Hide" : "Show") {
                    if shown { visible.remove(field.name) } else { visible.insert(field.name) }
                }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                .accessibilityLabel(shown ? Text("Hide \(field.label)") : Text("Show \(field.label)"))
            }
            if field.generate {
                Button("Generate") { generatingFor = field.name }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .accessibilityLabel("Generate a password")
            }
        }
    }

    @ViewBuilder
    private var notesInput: some View {
        if let detail, detail.hasNotes, originalNotes == nil {
            Button("Edit the notes") { loadNotes(detail.info.id) }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
        } else {
            TextEditor(text: $notes)
                .font(.ui(14))
                .foregroundStyle(Palette.tinta)
                .tint(Palette.cobalto)
                .scrollContentBackground(.hidden)
                .focused($focus, equals: "notes")
                .frame(minHeight: 90)
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(Palette.papel)
                .overlay(Rectangle().strokeBorder(focus == "notes" ? Palette.cobalto : Palette.linea,
                                                  lineWidth: focus == "notes" ? 1.5 : 1))
        }
    }

    private func labelled<Content: View>(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(label)
            content()
        }
    }

    /// A field's own name (a `String`), shown as is.
    @_disfavoredOverload
    private func labelled<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(label)
            content()
        }
    }

    // MARK: Work

    private func prepare() async {
        guard !prepared else { return }
        prepared = true
        do {
            switch request {
            case .edit(let id):
                let loaded = try await model.run { try $0.item(id: id) }
                detail = loaded
                title = loaded.info.title
                values = ItemDraft.plainValues(loaded)
                await loadSiblings()
            case .create(let chosen):
                kind = chosen
                projects = try await model.run { try $0.projects(vaultId: nil) }
                    .sorted { ($0.vault, $0.name) < ($1.vault, $1.name) }
                projectId = (projects.first { $0.vault == "Personal" && $0.name == "General" } ?? projects.first)?.id
                focus = "title"
                #if DEBUG
                if Snapshot.takeGenerator() { generatingFor = "password" }
                #endif
            }
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    private func loadSiblings() async {
        guard let project = detail?.info.projectId ?? projectId else { return }
        let query = ItemQuery(projectId: project)
        siblings = (try? await model.run { try $0.items(query: query) }) ?? []
    }

    private func loadNotes(_ id: String) {
        Task {
            do {
                let current = try await model.run { try $0.notes(id: id) } ?? ""
                originalNotes = current
                notes = current
            } catch {
                problem = describe(error)
            }
        }
    }

    private func save() {
        guard canSave else { return }
        focus = nil
        busy = true
        problem = nil
        let specs = fields, typed = values, titleNow = title, siteNow = url, notesNow = notes
        let notesBefore = originalNotes, project = projects.first { $0.id == projectId }, kindNow = kind
        let current = detail
        Task {
            do {
                let info: ItemInfo
                if let current {
                    let edit = ItemDraft.edit(of: current, title: titleNow, specs: specs, typed: typed,
                                              site: siteNow, notes: notesNow, notesBefore: notesBefore)
                    let id = current.info.id
                    info = try await model.run { try $0.editItem(id: id, edit: edit) }
                } else {
                    let input = ItemDraft.newItem(kind: kindNow, title: titleNow, project: project, specs: specs,
                                                  typed: typed, site: siteNow, notes: notesNow)
                    info = try await model.run { try $0.createItem(input: input) }
                }
                forget()
                model.saved(info, created: current == nil)
            } catch KlavError.Locked {
                model.refresh()
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }

    /// Drops whatever the person typed or revealed.
    private func forget() {
        values = [:]
        visible = []
        notes = ""
        originalNotes = nil
        generatingFor = nil
    }
}

/// «Move to the trash», confirmed in a sheet rather than the system's
/// dialog: Return does nothing here, Escape cancels.
struct TrashSheet: View {
    @EnvironmentObject private var model: MacModel
    let item: ItemInfo
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Title("Move “\(item.title)” to the trash?", size: 20)
            Text("It stops showing on all your devices.")
                .font(.ui(14)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if let problem { Notice(text: problem) }
            HStack(spacing: 8) {
                Spacer()
                Button("Cancel") { model.trashing = nil }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button(busy ? "Moving…" : "Move to the trash") { Task { await trash() } }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(busy)
            }
            .padding(.top, 6)
        }
        .padding(24)
        .frame(width: 400)
        .background(Palette.papel)
    }

    private func trash() async {
        busy = true
        defer { busy = false }
        problem = nil
        do {
            try await model.trash(item)
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }
}
