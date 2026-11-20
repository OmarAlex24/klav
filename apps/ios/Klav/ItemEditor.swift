import SwiftUI

/// Creates an item, or edits one. Secret values are never pre-filled: an
/// empty secret field keeps what the item has.
struct ItemEditor: View {
    enum Mode {
        case create
        case edit(ItemDetail)
    }

    let mode: Mode
    let saved: (ItemInfo) -> Void

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var typeSize

    @State private var kind: Kind = .login
    @State private var projects: [ProjectInfo] = []
    @State private var projectId: String?
    @State private var title = ""
    @State private var values: [String: String] = [:]
    @State private var visible: Set<String> = []
    @State private var url = ""
    @State private var notes = ""
    @State private var originalNotes: String?
    @State private var busy = false
    @State private var problem: String?
    @State private var prepared = false
    /// The field the generator sheet is for.
    @State private var generatingFor: String?
    @FocusState private var focus: String?

    private var editing: ItemDetail? {
        if case .edit(let detail) = mode { return detail }
        return nil
    }

    /// The site the generator follows: the URL being typed, or the item's first.
    private var generatorSite: String? {
        let typed = url.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { return typed }
        return editing?.info.confirmedUrls.first
    }

    private var fields: [FieldSpec] {
        guard let detail = editing else { return ItemDraft.templateFields(kind) }
        return ItemDraft.editFields(detail)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Title(editing == nil ? "New item" : "Edit", size: 22)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.horizontal, 20)
            .frame(minHeight: 64)
            .overlay(alignment: .bottom) { Rule() }

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if editing == nil {
                        kindPicker
                        labelled("Where") { projectPicker }
                    }
                    labelled("Title") {
                        TextField("Title", text: $title, prompt: placeholder("GitHub, Bank, Test server…"))
                            .focused($focus, equals: "title")
                            .inputBox(focused: focus == "title")
                    }
                    ForEach(fields) { field in
                        labelled(field.label) { input(field) }
                    }
                    if kind == .login || editing?.info.kind == .login {
                        labelled(editing == nil ? "Site" : "Add a site") {
                            TextField("Site", text: $url, prompt: placeholder(String("https://github.com")))
                                .keyboardType(.URL)
                                .focused($focus, equals: "url")
                                .inputBox(focused: focus == "url")
                        }
                    }
                    labelled("Notes") { notesInput }

                    if let pending = editing?.info.pendingUrls, !pending.isEmpty {
                        // Any version the person saves is hers: all its
                        // sites count from then on (ADR 0030 §7).
                        Notice(text: String(localized: "Saving also confirms the sites an agent added: \(pending.joined(separator: ", ")). To drop them, use Remove on the item instead."),
                               tone: .info)
                    }

                    if let problem { Notice(text: problem) }

                    Button(action: save) {
                        Text(busy ? "Saving…" : (editing == nil ? "Save to the vault" : "Save the changes"))
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(busy || title.trimmingCharacters(in: .whitespaces).isEmpty)
                    .padding(.top, 6)
                }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(20)
            }
            .scrollDismissesKeyboard(.interactively)
        }
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
        .onChange(of: model.inForeground) { _, foreground in
            // Typed secrets shown with «Show» are masked again whenever the
            // app leaves the screen, like the item's own fields.
            if !foreground { visible = [] }
        }
    }

    // MARK: Pieces

    /// The kind as square segments; the chosen one in ink.
    private var kindPicker: some View {
        HStack(spacing: -1) {
            ForEach(ItemDraft.creatable, id: \.self) { option in
                Button {
                    kind = option
                    values = [:]
                } label: {
                    Text(ItemDraft.shortLabel(option))
                        .font(.ui(14, kind == option ? .medium : .regular))
                        .foregroundStyle(kind == option ? Palette.botonTexto : Palette.tinta)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .padding(.horizontal, 6)
                        .frame(maxWidth: .infinity, minHeight: 44)
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
                Button(project.vault + " / " + project.name) { projectId = project.id }
            }
        } label: {
            HStack {
                Text(projects.first { $0.id == projectId }.map { "\($0.vault) / \($0.name)" } ?? String(localized: "Choose a project"))
                    .foregroundStyle(Palette.tinta)
                Spacer()
                Text("Change").font(.ui(14)).foregroundStyle(Palette.gris)
            }
            .inputBox(focused: false)
        }
        .accessibilityLabel("Where to save it")
    }

    @ViewBuilder
    private func input(_ field: FieldSpec) -> some View {
        let binding = Binding(get: { values[field.name] ?? "" }, set: { values[field.name] = $0 })
        // With accessibility text «Show» and «Generate» go under the box,
        // or they would break inside their words.
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(spacing: 8))
        layout {
            Group {
                if field.secret && !visible.contains(field.name) {
                    SecureField(field.label, text: binding, prompt: placeholder(field.placeholder))
                } else {
                    TextField(field.label, text: binding, prompt: placeholder(field.placeholder))
                }
            }
            .focused($focus, equals: field.name)
            .inputBox(focused: focus == field.name, font: field.secret ? .mono(15, relativeTo: .body) : .ui(16))
            if field.secret || field.generate {
                HStack(spacing: 8) {
                    if field.secret {
                        Button(visible.contains(field.name) ? "Hide" : "Show") {
                            if visible.contains(field.name) { visible.remove(field.name) } else { visible.insert(field.name) }
                        }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .frame(minHeight: 48)
                        .accessibilityLabel(visible.contains(field.name) ? Text("Hide \(field.label)") : Text("Show \(field.label)"))
                    }
                    if field.generate {
                        Button("Generate") { generatingFor = field.name }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .accessibilityLabel("Generate a password")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var notesInput: some View {
        if let detail = editing, detail.hasNotes, originalNotes == nil {
            Button("Edit the notes") { loadNotes(detail.info.id) }
                .buttonStyle(SecondaryButtonStyle())
        } else {
            TextEditor(text: $notes)
                .font(.ui(16))
                .foregroundStyle(Palette.tinta)
                .tint(Palette.cobalto)
                .scrollContentBackground(.hidden)
                .focused($focus, equals: "notes")
                .frame(minHeight: 110)
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
        guard !prepared, let service = model.service else { return }
        prepared = true
        if let detail = editing {
            title = detail.info.title
            values = ItemDraft.plainValues(detail)
            return
        }
        do {
            projects = try await service.run { core, _ in try core.projects(vaultId: nil) }
                .sorted { ($0.vault, $0.name) < ($1.vault, $1.name) }
            projectId = (projects.first { $0.vault == "Personal" && $0.name == "General" } ?? projects.first)?.id
        } catch {
            problem = describe(error)
        }
    }

    private func loadNotes(_ id: String) {
        guard let service = model.service else { return }
        Task {
            do {
                let current = try await service.run { core, _ in try core.notes(id: id) } ?? ""
                originalNotes = current
                notes = current
            } catch {
                problem = describe(error)
            }
        }
    }

    private func save() {
        guard let service = model.service else { return }
        focus = nil
        busy = true
        problem = nil
        let titleNow = title
        let siteNow = url
        let specs = fields
        let typed = values
        let detail = editing
        let notesNow = notes
        let notesBefore = originalNotes
        let project = projects.first { $0.id == projectId }
        let kindNow = kind

        Task {
            do {
                let info: ItemInfo
                if let detail {
                    let edit = ItemDraft.edit(of: detail, title: titleNow, specs: specs, typed: typed,
                                              site: siteNow, notes: notesNow, notesBefore: notesBefore)
                    let id = detail.info.id
                    info = try await service.run { core, _ in try core.editItem(id: id, edit: edit) }
                } else {
                    let input = ItemDraft.newItem(kind: kindNow, title: titleNow, project: project, specs: specs,
                                                  typed: typed, site: siteNow, notes: notesNow)
                    info = try await service.run { core, _ in try core.createItem(input: input) }
                }
                model.show(Toast(text: detail == nil ? String(localized: "Saved to the vault.") : String(localized: "Changes saved.")))
                saved(info)
                dismiss()
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }
}
