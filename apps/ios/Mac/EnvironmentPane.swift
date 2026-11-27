import SwiftUI

/// One environment (ADR 0032 §6), in the vault's right pane: its variables
/// with their values as noise until «Show», «Show» and «Copy» on each
/// (klavd asks for Touch ID every time in a protected one, or the master
/// password where there is none), where a reference comes from, what an
/// agent changed, the form to add or change a variable, the protected flag
/// and the trash. Values go when the page closes or Klav locks.
struct EnvironmentDetailView: View {
    @EnvironmentObject private var model: MacModel
    let projectId: String
    let name: String

    @State private var detail: EnvironmentDetailInfo?
    @State private var reveal = EnvironmentReveal()
    @State private var draft = VariableDraft()
    @State private var problem: String?
    @State private var formProblem: String?
    @State private var busy = false
    @State private var confirmTrash = false

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
        .onChange(of: model.phase) { _, phase in if phase != .unlocked { reveal.hideAll() } }
        .onDisappear { reveal.hideAll() }
        .confirmationDialog(Text("Move “\(name)” to the trash?"), isPresented: $confirmTrash) {
            Button("Move to the trash", role: .destructive) { Task { await trash() } }
        } message: {
            Text("Agents and klav run stop finding it. You can restore it from the trash with the CLI.")
        }
    }

    @ViewBuilder
    private func content(_ detail: EnvironmentDetailInfo) -> some View {
        let env = detail.info
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                IconView(icon: .layers, size: 22)
                    .foregroundStyle(Palette.tinta)
                    .frame(width: 44, height: 44)
                    .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: env.name).font(.mono(24)).foregroundStyle(Palette.tinta)
                    Text(verbatim: "\(Kind.environment.shortName) · \(env.vault) / \(env.project)")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                }
                Spacer(minLength: 12)
            }
            if env.protected {
                ProtectedNotice(text: EnvironmentWords.protectedNotice).padding(.top, 18)
            }
            if let changes = detail.agentChanges, !changes.variables.isEmpty {
                Notice(text: EnvironmentWords.agentChanged(changes)).padding(.top, 14)
            }
            if let problem { Notice(text: problem).padding(.top, 14) }

            VStack(spacing: 0) {
                if detail.variables.isEmpty {
                    Text("No variables yet.")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                }
                ForEach(Array(detail.variables.enumerated()), id: \.element.name) { index, variable in
                    if index > 0 { Rule() }
                    variableRow(variable)
                }
            }
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
            .padding(.top, 24)

            if model.canChangeItems {
                form.padding(.top, 28)
                Toggle(isOn: Binding(get: { env.protected }, set: { on in Task { await protect(on) } })) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Protect this environment").font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                        Text("Touch ID for every value, and agents ask every time. Turning it off asks for Touch ID.")
                            .font(.ui(12.5)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(SquareToggleStyle())
                .disabled(busy)
                .padding(.top, 28)

                Button("Move to the trash…") { confirmTrash = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(busy)
                    .padding(.top, 24)
            }
        }
    }

    private func variableRow(_ v: VariableInfo) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: v.name).font(.mono(12.5).weight(.medium)).foregroundStyle(Palette.tinta)
                MaskedValue(value: reveal.value(v.name), font: .mono(13))
                Text(verbatim: EnvironmentWords.origin(v)).font(.ui(11.5)).foregroundStyle(Palette.gris)
            }
            Spacer(minLength: 8)
            HStack(spacing: 6) {
                SmallAction(title: reveal.isShown(v.name) ? "Hide" : "Show",
                            label: reveal.isShown(v.name) ? String(localized: "Hide \(v.name)") : String(localized: "Show \(v.name)")) {
                    Task { await toggle(v) }
                }
                IconButton(icon: .copy, label: "Copy", size: 26) { Task { await copy(v) } }
                    .help(String(localized: "Copy \(v.name)"))
                if model.canChangeItems {
                    SmallAction(title: "Change", label: String(localized: "Change \(v.name)")) {
                        reveal.hide(v.name)
                        draft = VariableDraft(name: v.name, source: v.reference == nil ? .value : .reference)
                        formProblem = nil
                    }
                    SmallAction(title: "Remove", label: String(localized: "Remove \(v.name)")) {
                        Task { await save(EnvironmentRules.remove(v.name)) }
                    }
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel("Add variable")
            HStack(spacing: 8) {
                TextField(String(localized: "NAME"), text: $draft.name)
                    .textFieldStyle(.plain)
                    .font(.mono(13)).foregroundStyle(Palette.tinta)
                    .padding(.horizontal, 10).padding(.vertical, 8)
                    .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                    .frame(width: 200)
                Picker(String(localized: "Where the value comes from"), selection: $draft.source) {
                    Text("Value").tag(VariableDraft.Source.value)
                    Text("Reference").tag(VariableDraft.Source.reference)
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .fixedSize()
            }
            HStack(spacing: 8) {
                Group {
                    if draft.source == .value {
                        SecureField(String(localized: "Value"), text: $draft.text)
                    } else {
                        TextField(String(localized: "klav://Vault/Project/Item/field"), text: $draft.text)
                    }
                }
                .textFieldStyle(.plain)
                .font(.mono(13)).foregroundStyle(Palette.tinta)
                .padding(.horizontal, 10).padding(.vertical, 8)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .onSubmit { Task { await addVariable() } }
                Button(busy ? String(localized: "Saving…") : String(localized: "Save")) { Task { await addVariable() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .disabled(busy)
            }
            if let formProblem { Notice(text: formProblem) }
        }
    }

    // MARK: Loading, values and edits

    private func load() async {
        let projectId = projectId, name = name
        reveal.hideAll()
        do {
            detail = try await model.run { try $0.environment(projectId: projectId, name: name) }
            problem = detail == nil ? String(localized: "This environment is no longer here.") : nil
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    /// One value, asked of klavd every time: a protected one asks for
    /// Touch ID, or for the master password in the app's sheet.
    private func value(_ v: VariableInfo) async -> String? {
        let reference = v.resolve
        do {
            return try await model.value({ try $0.variableValue(reference: reference) },
                                         withPassword: { try $0.variableValueWithPassword(reference: reference, password: $1) })
        } catch is CancellationError {
            return nil
        } catch {
            problem = describe(error)
            return nil
        }
    }

    private func toggle(_ v: VariableInfo) async {
        if reveal.isShown(v.name) {
            reveal.hide(v.name)
        } else if let value = await value(v) {
            reveal.show(v.name, value)
        }
    }

    private func copy(_ v: VariableInfo) async {
        if let value = await value(v) { model.copy(value) }
    }

    private func addVariable() async {
        formProblem = draft.problem
        guard let edit = draft.edit else { return }
        // The typed value leaves the field as soon as it is sent.
        draft = VariableDraft()
        await save(edit)
    }

    private func protect(_ on: Bool) async {
        await save(EnvironmentRules.protect(on), lowering: !on)
    }

    /// Saves `edit`. Lowering the protection asks klavd for Touch ID, or
    /// the master password over the window where there is none.
    private func save(_ edit: EnvironmentEditInput, lowering: Bool = false) async {
        let projectId = projectId, name = name
        busy = true
        defer { busy = false }
        do {
            try await model.withPresenceResult(String(localized: "Lower the protection of “\(name)”")) { engine, password in
                try engine.saveEnvironmentWithPassword(projectId: projectId, name: name, edit: edit, password: password)
            } done: { saved in
                model.show(Toast(text: EnvironmentWords.saved(saved)))
                Task { await load() }
            }
            problem = nil
        } catch KlavError.Locked {
            model.refresh()
        } catch is CancellationError {
        } catch {
            problem = describe(error)
        }
    }

    private func trash() async {
        let projectId = projectId, name = name
        busy = true
        defer { busy = false }
        do {
            try await model.withPresenceResult(String(localized: "Lower the protection of “\(name)”")) { engine, password in
                try engine.trashEnvironmentWithPassword(projectId: projectId, name: name, password: password)
            } done: { _ in
                model.show(Toast(text: String(localized: "Moved to the trash")))
                model.selectedItem = nil
                model.changed()
            }
        } catch KlavError.Locked {
            model.refresh()
        } catch is CancellationError {
        } catch {
            problem = describe(error)
        }
    }
}

/// «New environment»: its project, its name and the protected flag, on by
/// itself for `production` and `prod` until the person changes it.
struct NewEnvironmentSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss

    @State private var projects: [ProjectInfo] = []
    @State private var projectId = ""
    @State private var name = ""
    @State private var protected = false
    @State private var touched = false
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Title("New environment", size: 20)
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 22)
            .frame(height: 56)
            .overlay(alignment: .bottom) { Rule() }

            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    FieldLabel("Project")
                    Picker(String(localized: "Project"), selection: $projectId) {
                        ForEach(projects, id: \.id) { project in
                            Text(verbatim: project.displayWithRepo).tag(project.id)
                        }
                    }
                    .labelsHidden()
                }
                VStack(alignment: .leading, spacing: 6) {
                    FieldLabel("Name")
                    TextField(String(localized: "development"), text: $name)
                        .textFieldStyle(.plain)
                        .font(.mono(13)).foregroundStyle(Palette.tinta)
                        .padding(.horizontal, 10).padding(.vertical, 8)
                        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                        .onChange(of: name) { _, value in
                            if !touched { protected = EnvironmentRules.protectedByDefault(value) }
                        }
                        .onSubmit { Task { await create() } }
                }
                Toggle(isOn: Binding(get: { protected }, set: { protected = $0; touched = true })) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Protect this environment").font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                        Text("Touch ID for every value, and agents ask every time. Turning it off asks for Touch ID.")
                            .font(.ui(12.5)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(SquareToggleStyle())
                if let problem { Notice(text: problem) }
                Button(busy ? String(localized: "Creating…") : String(localized: "Create")) { Task { await create() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .disabled(busy || projectId.isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(22)
        }
        .frame(width: 460)
        .background(Palette.papel)
        .task {
            projects = (try? await model.run { try $0.projects(vaultId: nil) }) ?? []
            if projectId.isEmpty { projectId = projects.first?.id ?? "" }
        }
    }

    private func create() async {
        let value = name.trimmingCharacters(in: .whitespaces)
        guard EnvironmentRules.isEnvironmentName(value) else {
            problem = String(localized: "Lowercase letters, digits, - and _ (up to 64), like development.")
            return
        }
        let projectId = projectId, protected = protected
        busy = true
        defer { busy = false }
        do {
            let saved = try await model.run {
                try $0.saveEnvironment(projectId: projectId, name: value, edit: EnvironmentRules.create(protected: protected))
            }
            model.changed()
            model.selectedItem = saved.id
            dismiss()
        } catch {
            problem = describe(error)
        }
    }
}
