import SwiftUI

extension KlavCore {
    /// Face ID (or the passcode) first, every time, for a value a protected
    /// environment reaches (ADR 0032 §3.1): the item page calls it before
    /// `fieldValue`, `notes`, `totp` and `previousPassword`. A device that
    /// cannot ask hands nothing out. Call it off the main thread.
    func confirmProtection(id: String, keystore: PlatformKeystore) throws {
        guard try valueProtection(id: id) != nil else { return }
        do {
            try keystore.confirmOwner(reason: EnvironmentWords.protectedItemReason)
        } catch KeystoreError.Unavailable {
            throw KlavError.BiometryUnavailable(message: "set a passcode to use protected values")
        } catch let error as KeystoreError {
            throw KlavError.BiometryFailed(message: "\(error)")
        }
    }
}

extension EnvironmentWords {
    /// Face ID's words before a value of an item a protected environment
    /// points to.
    static var protectedItemReason: String {
        String(localized: "Show a value protected by an environment", comment: "Face ID prompt")
    }

    /// Face ID's words before a value of a protected environment.
    static func showReason(_ environment: String) -> String {
        String(localized: "Show a value of “\(environment)”", comment: "Face ID prompt: the environment")
    }

    /// Face ID's words before a protected environment goes to the trash.
    static func trashReason(_ environment: String) -> String {
        String(localized: "Move “\(environment)” to the trash", comment: "Face ID prompt: the environment")
    }

    /// Face ID's words before lowering an environment's protection.
    static func lowerReason(_ environment: String) -> String {
        String(localized: "Lower the protection of “\(environment)”", comment: "Face ID prompt: the environment")
    }
}

/// One environment on the iPhone (ADR 0032 §6): its variables with their
/// values as noise until «Show», «Show» and «Copy» on each (`KlavCore` asks
/// for Face ID every time in a protected one), where a reference comes
/// from, what an agent changed, the form to add or change a variable, the
/// protected flag and the trash. Values go when the screen closes or the
/// app leaves the foreground.
struct EnvironmentScreen: View {
    let projectId: String
    let name: String

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var detail: EnvironmentDetailInfo?
    @State private var reveal = EnvironmentReveal()
    @State private var draft = VariableDraft()
    @State private var problem: String?
    @State private var formProblem: String?
    @State private var busy = false
    @State private var confirmTrash = false

    var body: some View {
        VStack(spacing: 0) {
            bar
            ScrollView {
                if let detail {
                    content(detail)
                } else if let problem {
                    Notice(text: problem).padding(20)
                }
            }
        }
        .background(Palette.papel)
        .toolbar(.hidden, for: .navigationBar)
        .task(id: model.generation) { await load() }
        .onChange(of: model.inForeground) { _, foreground in if !foreground { reveal.hideAll() } }
        .onDisappear { reveal.hideAll() }
        .confirmationDialog(Text("Move “\(name)” to the trash?"), isPresented: $confirmTrash, titleVisibility: .visible) {
            Button("Move to the trash", role: .destructive) { Task { await trash() } }
        } message: {
            Text("Agents and klav run stop finding it. You can restore it from the trash with the CLI.")
        }
    }

    private var bar: some View {
        HStack {
            Button {
                dismiss()
            } label: {
                HStack(spacing: 4) {
                    IconView(icon: .back)
                    Text("Your vault").font(.ui(15))
                }
                .foregroundStyle(Palette.gris)
                .frame(minHeight: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Spacer()
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 56)
        .overlay(alignment: .bottom) { Rule() }
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
                Text(verbatim: env.name).font(.mono(26, relativeTo: .title)).foregroundStyle(Palette.tinta)
            }
            Text(verbatim: "\(Kind.environment.shortName) · \(env.vault) / \(env.project)")
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .padding(.top, 6)
            if env.protected {
                ProtectedNotice(text: EnvironmentWords.protectedNotice).padding(.top, 16)
            }
            if let changes = detail.agentChanges, !changes.variables.isEmpty {
                Notice(text: EnvironmentWords.agentChanged(changes)).padding(.top, 14)
            }
            if let problem { Notice(text: problem).padding(.top, 14) }

            VStack(spacing: 0) {
                if detail.variables.isEmpty {
                    Text("No variables yet.")
                        .font(.ui(15)).foregroundStyle(Palette.gris)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                }
                ForEach(Array(detail.variables.enumerated()), id: \.element.name) { index, variable in
                    if index > 0 { Rule() }
                    variableRow(variable, protected: env.protected)
                }
            }
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
            .padding(.top, 22)

            if !model.readOnly {
                form.padding(.top, 28)
                Toggle(isOn: Binding(get: { env.protected }, set: { on in Task { await save(EnvironmentRules.protect(on)) } })) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Protect this environment").font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                        Text("Face ID for every value, and agents ask every time. Turning it off asks for Face ID.")
                            .font(.ui(13)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(SquareToggleStyle())
                .disabled(busy)
                .padding(.top, 28)

                Button("Move to the trash…") { confirmTrash = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                    .disabled(busy)
                    .padding(.top, 24)
            }
        }
        .padding(20)
    }

    private func variableRow(_ v: VariableInfo, protected: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(verbatim: v.name).font(.mono(14, relativeTo: .body).weight(.medium)).foregroundStyle(Palette.tinta)
                Spacer(minLength: 8)
                Button(reveal.isShown(v.name) ? "Hide" : "Show") { Task { await toggle(v) } }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityLabel(Text(reveal.isShown(v.name) ? "Hide \(v.name)" : "Show \(v.name)"))
                IconButton(icon: .copy, label: "Copy", size: 32) { Task { await copy(v) } }
                    .accessibilityLabel(Text("Copy \(v.name)"))
                if !model.readOnly {
                    Menu {
                        Button("Change") {
                            reveal.hide(v.name)
                            draft = VariableDraft(name: v.name, source: v.reference == nil ? .value : .reference)
                            formProblem = nil
                        }
                        Button("Remove", role: .destructive) { Task { await save(EnvironmentRules.remove(v.name)) } }
                    } label: {
                        Text(verbatim: "···").font(.ui(15, .medium)).foregroundStyle(Palette.gris)
                            .frame(width: 32, height: 32)
                            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                    }
                    .accessibilityLabel(Text("More for \(v.name)"))
                }
            }
            MaskedValue(value: reveal.value(v.name), font: .mono(14, relativeTo: .body))
            Text(verbatim: EnvironmentWords.origin(v)).font(.ui(13)).foregroundStyle(Palette.gris)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel("Add variable")
            TextField(String(localized: "NAME"), text: $draft.name)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .font(.mono(15, relativeTo: .body)).foregroundStyle(Palette.tinta)
                .padding(.horizontal, 12).frame(minHeight: 44)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            Picker(String(localized: "Where the value comes from"), selection: $draft.source) {
                Text("Value").tag(VariableDraft.Source.value)
                Text("Reference").tag(VariableDraft.Source.reference)
            }
            .pickerStyle(.segmented)
            Group {
                if draft.source == .value {
                    SecureField(String(localized: "Value"), text: $draft.text)
                } else {
                    TextField(String(localized: "klav://Vault/Project/Item/field"), text: $draft.text)
                        .textInputAutocapitalization(.never)
                }
            }
            .autocorrectionDisabled()
            .font(.mono(15, relativeTo: .body)).foregroundStyle(Palette.tinta)
            .padding(.horizontal, 12).frame(minHeight: 44)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            if let formProblem { Notice(text: formProblem) }
            Button(busy ? String(localized: "Saving…") : String(localized: "Save")) { Task { await addVariable() } }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy)
        }
    }

    // MARK: Loading, values and edits

    private func load() async {
        guard let service = model.service else { return }
        let projectId = projectId, name = name
        reveal.hideAll()
        do {
            detail = try await service.run { core, _ in try core.environment(projectId: projectId, name: name) }
            problem = detail == nil ? String(localized: "This environment is no longer here.") : nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
    }

    /// One value, asked of `KlavCore` every time: in a protected
    /// environment it shows Face ID first.
    private func value(_ v: VariableInfo) async -> String? {
        guard let service = model.service else { return nil }
        let reference = v.resolve, reason = EnvironmentWords.showReason(name)
        do {
            return try await service.run { core, keystore in
                try core.variableValue(reference: reference, reason: reason, keystore: keystore)
            }
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

    /// Saves `edit`; lowering the protection asks for Face ID in `KlavCore`.
    private func save(_ edit: EnvironmentEditInput) async {
        guard let service = model.service else { return }
        let projectId = projectId, name = name, reason = EnvironmentWords.lowerReason(name)
        busy = true
        defer { busy = false }
        do {
            let saved = try await service.run { core, keystore in
                try core.saveEnvironment(projectId: projectId, name: name, edit: edit, reason: reason, keystore: keystore)
            }
            model.show(Toast(text: EnvironmentWords.saved(saved)))
            model.changed()
            await load()
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
    }

    private func trash() async {
        guard let service = model.service else { return }
        let projectId = projectId, name = name, reason = EnvironmentWords.trashReason(name)
        busy = true
        defer { busy = false }
        do {
            _ = try await service.run { core, keystore in
                try core.trashEnvironment(projectId: projectId, name: name, reason: reason, keystore: keystore)
            }
            model.changed()
            model.show(Toast(text: String(localized: "Moved to the trash.")))
            dismiss()
        } catch {
            problem = describe(error)
        }
    }
}
