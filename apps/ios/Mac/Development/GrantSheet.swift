import SwiftUI

/// The editor's state: the change the person is making, from the grant in
/// force. Never filled from anything an agent wrote (T191).
struct GrantDraft: Equatable {
    var projects: Set<String>
    /// Permission → effect; absent: its default.
    var effects: [String: String]
    var defaults: [String: String]
    var fillSites: [String]
    var hours: [TimeWindowInfo]
    var expires: UInt64?
    var rotateRemoved = false

    init(_ grant: GrantEditorInfo) {
        let policy = grant.editor
        projects = Set(grant.projects.map(\.projectId))
        effects = Dictionary(policy?.permissions.compactMap { p in p.effect.map { (p.permission, $0) } } ?? [],
                             uniquingKeysWith: { _, last in last })
        defaults = Dictionary(policy?.permissions.map { ($0.permission, $0.defaultEffect) } ?? [],
                              uniquingKeysWith: { _, last in last })
        fillSites = policy?.fillSites ?? []
        hours = policy?.hours ?? []
        expires = policy?.expiresAtSecs
    }

    /// What prepare and apply send: the same value both times.
    func input(order: [String]) -> GrantChangeInput {
        GrantChangeInput(
            projectIds: order.filter { projects.contains($0) } + projects.subtracting(order).sorted(),
            permissions: GrantWords.permissions.compactMap { p in
                effects[p].map { PermissionSettingInput(permission: p, effect: $0) }
            },
            fillSites: fillSites, hours: hours, expiresAtSecs: expires, rotateRemoved: rotateRemoved)
    }
}

/// «Change permissions…» (F3): the editor, then the review sheet with only
/// the differences `klavd` computed. What is signed is what it shows.
struct GrantSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let agentId: String

    @State private var grant: GrantEditorInfo?
    @State private var original: GrantDraft?
    @State private var draft: GrantDraft?
    @State private var projects: [ProjectInfo] = []
    @State private var preview: GrantChangePreviewInfo?
    @State private var busy = false
    @State private var problem: String?
    @State private var newSite = ""
    @State private var adding = NewWindow()

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let preview, let draft {
                        review(preview, draft)
                    } else if let grant, draft != nil {
                        editor(grant)
                    } else if problem == nil {
                        ProgressView().controlSize(.small).padding(.top, 40).frame(maxWidth: .infinity)
                    }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            footer
        }
        .background(Palette.papel)
        .task { await load() }
        // Widening on a Mac without Touch ID asks for the master password
        // (P8): over this sheet, where the person is.
        .sheet(item: model.passwordPromptHere(inSheet: true)) { prompt in
            PasswordSheet(prompt: prompt).environmentObject(model)
        }
    }

    // MARK: The editor

    @ViewBuilder
    private func editor(_ grant: GrantEditorInfo) -> some View {
        Title("Change permissions", size: 22)
        Text("For “\(AgentText.line(grant.name, max: 64))”. Next you’ll see only what changes, before anything is signed.")
            .font(.ui(13)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 6)

        SectionLabel("Projects").padding(.top, 24).padding(.bottom, 8)
        VStack(spacing: 8) {
            ForEach(projects, id: \.id) { p in
                Toggle(isOn: projectBinding(p.id)) {
                    Text(verbatim: "\(p.vault)/\(p.name)").font(.ui(14)).foregroundStyle(Palette.tinta)
                }
                .toggleStyle(SquareToggleStyle())
            }
        }

        SectionLabel("What it can do").padding(.top, 24).padding(.bottom, 8)
        FieldBlock {
            ForEach(Array(GrantWords.permissions.enumerated()), id: \.element) { index, p in
                if index > 0 { Rule() }
                permissionRow(p)
            }
        }

        SectionLabel("Where it fills").padding(.top, 24).padding(.bottom, 8)
        sites

        SectionLabel("Hours").padding(.top, 24).padding(.bottom, 8)
        hoursEditor

        SectionLabel("Expires").padding(.top, 24).padding(.bottom, 8)
        expiry
    }

    private func permissionRow(_ p: String) -> some View {
        let effect = draft?.effects[p]
        let fallback = draft?.defaults[p] ?? "deny"
        let bySites = p == "fill" && !(draft?.fillSites.isEmpty ?? true)
        return HStack(spacing: 12) {
            Text(verbatim: GrantWords.permissionTitle(p)).font(.ui(13)).foregroundStyle(Palette.tinta)
            Spacer(minLength: 8)
            if bySites {
                Text("Only on the sites below").font(.ui(12)).foregroundStyle(Palette.gris)
            } else {
                if effect != nil {
                    Button("Default") { draft?.effects[p] = nil }
                        .buttonStyle(.plain)
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .underline(true, color: Palette.linea)
                }
                EffectLadder(effect: effect ?? fallback, isDefault: effect == nil) { picked in
                    draft?.effects[p] = picked
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    @ViewBuilder
    private var sites: some View {
        Text("Empty: it fills wherever its permission allows.")
            .font(.ui(12)).foregroundStyle(Palette.gris)
        ForEach(draft?.fillSites ?? [], id: \.self) { site in
            HStack {
                Text(verbatim: site).font(.ui(14)).foregroundStyle(Palette.tinta)
                Spacer()
                SmallAction(title: "Remove") { draft?.fillSites.removeAll { $0 == site } }
            }
            .padding(.top, 6)
        }
        HStack(spacing: 8) {
            TextField("", text: $newSite, prompt: placeholder("github.com", font: .ui(14)))
                .textFieldStyle(.plain)
                .inputBox(focused: false, font: .ui(14))
                .onSubmit(addSite)
            Button("Add", action: addSite)
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .disabled(newSite.trimmingCharacters(in: .whitespaces).isEmpty)
                .fixedSize()
        }
        .padding(.top, 8)
    }

    private func addSite() {
        let site = newSite.trimmingCharacters(in: .whitespaces).lowercased()
        guard !site.isEmpty, draft?.fillSites.contains(site) == false else { return }
        draft?.fillSites.append(site)
        // With sites, `fill` has no effect of its own.
        draft?.effects["fill"] = nil
        newSite = ""
    }

    @ViewBuilder
    private var hoursEditor: some View {
        Text(draft?.hours.isEmpty ?? true ? "Always: at any hour." : "Only inside these hours, on this Mac’s clock unless it says otherwise.")
            .font(.ui(12)).foregroundStyle(Palette.gris)
        ForEach(Array((draft?.hours ?? []).enumerated()), id: \.offset) { index, w in
            HStack {
                Text(verbatim: GrantWords.window(w)).font(.ui(14)).foregroundStyle(Palette.tinta)
                Spacer()
                SmallAction(title: "Remove") { draft?.hours.remove(at: index) }
            }
            .padding(.top, 6)
        }
        HStack(spacing: 4) {
            ForEach(GrantWords.weekdays, id: \.self) { day in
                let on = adding.days.contains(day)
                Button {
                    if on { adding.days.remove(day) } else { adding.days.insert(day) }
                } label: {
                    Text(verbatim: GrantWords.dayName(day)).font(.ui(11.5, .medium))
                        .foregroundStyle(on ? Palette.botonTexto : Palette.tinta)
                        .frame(width: 40, height: 26)
                        .background(on ? Palette.tinta : Palette.papel)
                        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
            }
        }
        .padding(.top, 10)
        HStack(spacing: 8) {
            TextField("", text: $adding.start, prompt: placeholder("09:00", font: .ui(14)))
                .textFieldStyle(.plain).inputBox(focused: false, font: .ui(14)).frame(width: 90)
            Text(verbatim: "–").foregroundStyle(Palette.gris)
            TextField("", text: $adding.end, prompt: placeholder("18:00", font: .ui(14)))
                .textFieldStyle(.plain).inputBox(focused: false, font: .ui(14)).frame(width: 90)
            Button("Add hours", action: addWindow)
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .disabled(adding.window == nil)
                .fixedSize()
        }
        .padding(.top, 8)
    }

    private func addWindow() {
        guard let w = adding.window else { return }
        draft?.hours.append(w)
        adding = NewWindow()
    }

    @ViewBuilder
    private var expiry: some View {
        Toggle(isOn: Binding(get: { draft?.expires != nil },
                             set: { on in draft?.expires = on ? (original?.expires ?? Self.inDays(30)) : nil })) {
            Text("Ends on a date").font(.ui(14)).foregroundStyle(Palette.tinta)
        }
        .toggleStyle(SquareToggleStyle())
        if let secs = draft?.expires {
            DatePicker("", selection: Binding(get: { Date(timeIntervalSince1970: TimeInterval(secs)) },
                                              set: { draft?.expires = UInt64(max(0, $0.timeIntervalSince1970)) }),
                       in: Date()..., displayedComponents: .date)
                .labelsHidden()
                .datePickerStyle(.field)
                .fixedSize()
                .padding(.top, 8)
        } else {
            Text("Never: it keeps this grant until you change it or revoke it.")
                .font(.ui(12)).foregroundStyle(Palette.gris).padding(.top, 6)
        }
    }

    private static func inDays(_ days: Int) -> UInt64 {
        UInt64(Date().addingTimeInterval(TimeInterval(days) * 86_400).timeIntervalSince1970)
    }

    private func projectBinding(_ id: String) -> Binding<Bool> {
        Binding(get: { draft?.projects.contains(id) ?? false },
                set: { on in if on { draft?.projects.insert(id) } else { draft?.projects.remove(id) } })
    }

    // MARK: The review sheet

    @ViewBuilder
    private func review(_ preview: GrantChangePreviewInfo, _ draft: GrantDraft) -> some View {
        let sheet = GrantReview(preview, touchID: model.touchIDReady)
        Title("Check what changes", size: 22)
        HStack(spacing: 0) {
            Rectangle().fill(preview.widens ? Palette.cobalto : Palette.tinta).frame(width: 2)
            Text(verbatim: sheet.headline)
                .font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 10).padding(.horizontal, 12)
        }
        .background(Palette.niebla)
        .padding(.top, 14)

        SectionLabel("Only the differences").padding(.top, 24).padding(.bottom, 8)
        FieldBlock {
            ForEach(Array(sheet.rows.enumerated()), id: \.offset) { index, row in
                if index > 0 { Rule() }
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(verbatim: row.text).font(.ui(14)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                    Spacer(minLength: 8)
                    if row.widens {
                        Tag(text: String(localized: "widens"), color: Palette.cobalto)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
        }

        if !preview.removedProjects.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: Binding(get: { draft.rotateRemoved },
                                     set: { on in Task { await rotateRemoved(on) } })) {
                    Text("Also change the key of the projects you take away")
                        .font(.ui(14)).foregroundStyle(Palette.tinta)
                }
                .toggleStyle(SquareToggleStyle())
                .disabled(busy)
                Text("It already has their keys. With an honest server it can’t use them any more; a dishonest one could still let it open what you add there later. Changing the keys wraps those projects’ items again and gives the other agents that hold them a new grant, without asking you.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 20)
        }

        Text("A new grant cancels this agent’s requests waiting for you.")
            .font(.ui(12)).foregroundStyle(Palette.gris)
            .padding(.top, 16)
        ForEach(preview.warnings, id: \.self) { warning in
            Notice(text: warning, tone: .info).padding(.top, 8)
        }
    }

    private func rotateRemoved(_ on: Bool) async {
        guard var next = draft else { return }
        next.rotateRemoved = on
        draft = next
        // The change goes into the sheet's digest: prepare it again
        // before anything can be signed.
        await prepare()
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: 10) {
            Spacer()
            if preview != nil {
                Button("Back") { preview = nil; problem = nil }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .disabled(busy)
                    .fixedSize()
                Button(busy ? model.waitingForPresence : String(localized: "Sign")) { Task { await sign() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy)
                    .fixedSize()
            } else {
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .keyboardShortcut(.cancelAction)
                    .fixedSize()
                Button("Review changes") { Task { await prepare() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || draft == nil || draft == original || draft?.projects.isEmpty == true)
                    .fixedSize()
            }
        }
        .padding(.horizontal, 20)
        .frame(height: 64)
        .overlay(alignment: .top) { Rule() }
    }

    // MARK: Calls

    private var order: [String] { grant?.projects.map(\.projectId) ?? [] }

    private func load() async {
        do {
            let id = agentId
            let (grant, projects) = try await model.run { engine in
                (try engine.grantEditor(id: id), try engine.projects(vaultId: nil))
            }
            guard grant.editable else {
                problem = GrantWords.readOnly(grant.readOnly ?? .noGrant, agent: grant.name).0
                return
            }
            self.grant = grant
            self.projects = projects
            original = GrantDraft(grant)
            draft = original
            #if DEBUG
            if Snapshot.reviewGrant {
                draft?.projects.insert("p1")
                draft?.effects["inject"] = "deny"
                await prepare()
                if UserDefaults.standard.bool(forKey: "KlavSign") { await sign() }
            }
            #endif
        } catch {
            problem = describe(error)
        }
    }

    private func prepare() async {
        guard let draft else { return }
        busy = true
        problem = nil
        defer { busy = false }
        do {
            preview = try await model.prepareGrantChange(agent: agentId, change: draft.input(order: order))
        } catch {
            preview = nil
            problem = describe(error)
        }
    }

    private func sign() async {
        guard let preview, let draft else { return }
        busy = true
        problem = nil
        defer { busy = false }
        do {
            try await model.applyGrantChange(preview, change: draft.input(order: order)) { _ in
                dismiss()
            }
        } catch KlavError.Security {
            // T188: the grant changed under the sheet; nothing was signed.
            problem = String(localized: "The grant changed while you were looking at it. Nothing was signed: go back and check it again.")
            self.preview = nil
            await load()
        } catch {
            problem = describe(error)
        }
    }
}

/// «Add hours»: days and a start and end, on this Mac's clock.
struct NewWindow: Equatable {
    var days: Set<String> = ["mon", "tue", "wed", "thu", "fri"]
    var start = ""
    var end = ""

    var window: TimeWindowInfo? {
        guard let s = Self.minutes(start), let e = Self.minutes(end), s != e else { return nil }
        return TimeWindowInfo(days: GrantWords.weekdays.filter { days.contains($0) && days.count < 7 },
                              startMinutes: s, endMinutes: e,
                              utcOffsetMinutes: Int16(TimeZone.current.secondsFromGMT() / 60))
    }

    static func minutes(_ text: String) -> UInt16? {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: ":")
        guard parts.count == 2, let h = UInt16(parts[0]), let m = UInt16(parts[1]), h < 24, m < 60 else { return nil }
        return h * 60 + m
    }
}
