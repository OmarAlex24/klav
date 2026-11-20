import SwiftUI

/// One item: its fields in a block with cross corners, secrets as noise
/// until shown, the live one-time code, its sites, the `klav://` reference
/// for agents, notes and editing.
struct ItemView: View {
    let id: String

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var detail: ItemDetail?
    /// Secret values the person chose to see, by field name.
    @State private var revealed: [String: String] = [:]
    @State private var notes: String?
    @State private var problem: String?
    @State private var editing = false
    @State private var confirmTrash = false
    /// The item's previous passwords (no values), and the ones shown.
    @State private var previous: [PreviousPasswordInfo] = []
    @State private var previousShown: [UInt32: String] = [:]
    /// An assisted change left a new password nobody confirmed (ADR 0022
    /// §5): when it was generated, if so.
    @State private var pending: PasswordHistoryInfo?
    /// Confirming or removing the sites an agent added.
    @State private var settlingSites = false

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
        .onChange(of: model.inForeground) { _, foreground in
            // Hidden again whenever the app leaves the screen.
            if !foreground { hideAll() }
        }
        .sheet(isPresented: $editing) {
            if let detail {
                ItemEditor(mode: .edit(detail)) { _ in
                    hideAll()
                    model.changed()
                }
                .environmentObject(model)
            }
        }
        .confirmationDialog(Text("Move “\(trashTitle)” to the trash?"),
                            isPresented: $confirmTrash, titleVisibility: .visible) {
            Button("Move to the trash", role: .destructive, action: trash)
        } message: {
            Text("It stops showing on all your devices.")
        }
    }

    private var trashTitle: String { detail?.info.title ?? "" }

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
            // Read-only after the deletion (ADR 0037 D-C).
            if !model.readOnly {
                Button("Edit") { editing = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .disabled(detail == nil)
            }
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 56)
        .overlay(alignment: .bottom) { Rule() }
    }

    @ViewBuilder
    private func content(_ detail: ItemDetail) -> some View {
        let info = detail.info
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                Tile(title: info.title, site: info.confirmedUrls.first, size: 44)
                Title(info.title, size: 28)
            }
            Text(verbatim: "\(info.kind.shortName) · \(info.vault) / \(info.project)")
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .padding(.top, 6)

            if let problem {
                Notice(text: problem).padding(.top, 14)
            }

            if let pending, pending.pending, !model.readOnly {
                PendingChangeCard(id: id, since: pending.pendingSince) {
                    hideAll()
                    model.changed()
                }
                .padding(.top, 18)
            }

            let shown = detail.fields.filter { $0.filled && $0.kind != .totp && $0.kind != .file }
            FieldBlock {
                ForEach(Array(shown.enumerated()), id: \.element.name) { index, field in
                    if index > 0 { Rule() }
                    FieldRow(field: field, revealed: revealed[field.name],
                             onToggle: { toggle(field) }, onCopy: { copy(field) })
                }
                if detail.hasTotp {
                    if !shown.isEmpty { Rule() }
                    codeRow(info)
                }
                // Only the sites the person confirmed: the ones an agent
                // added go below, apart (ADR 0030 §7).
                ForEach(Array(info.confirmedUrls.enumerated()), id: \.offset) { index, url in
                    if index > 0 || !shown.isEmpty || detail.hasTotp { Rule() }
                    siteRow(url)
                }
                if !shown.isEmpty || detail.hasTotp || !info.confirmedUrls.isEmpty { Rule() }
                referenceRow(info)
            }
            .padding(.top, 22)

            if !info.pendingUrls.isEmpty {
                agentSites(info)
            }

            if !previous.isEmpty {
                SectionLabel("Previous passwords").padding(.top, 28).padding(.bottom, 10)
                FieldBlock {
                    ForEach(Array(previous.enumerated()), id: \.element.index) { index, entry in
                        if index > 0 { Rule() }
                        PreviousPasswordRow(entry: entry, position: index + 1, count: previous.count,
                                            shown: previousShown[entry.index],
                                            onToggle: { togglePrevious(entry) }, onCopy: { copyPrevious(entry) })
                    }
                }
            }

            if detail.hasNotes {
                SectionLabel("Notes").padding(.top, 28).padding(.bottom, 10)
                DetailRow(alignment: .top, padded: false) {
                    MaskedValue(value: notes, font: .ui(15), hiddenWidth: 180)
                } actions: {
                    Button(notes == nil ? "Show" : "Hide") { toggleNotes() }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .accessibilityLabel(notes == nil ? "Show the notes" : "Hide the notes")
                }
            }

            if !info.tags.isEmpty {
                SectionLabel("Tags").padding(.top, 28).padding(.bottom, 8)
                Text(info.tags.joined(separator: ", "))
                    .font(.ui(15))
                    .foregroundStyle(Palette.tinta)
            }

            WhoUsedIt(itemId: info.id).id(info.id)

            let updated = Date(timeIntervalSince1970: TimeInterval(info.updatedAt) / 1000).formatted(.relative(presentation: .named))
            Text("Version \(info.version) · updated \(updated)")
                .font(.ui(13, relativeTo: .footnote))
                .foregroundStyle(Palette.gris)
                .padding(.top, 32)

            if !model.readOnly {
                Button("Move to the trash") { confirmTrash = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                    .padding(.top, 12)
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 22)
        .padding(.bottom, 48)
    }

    // MARK: Rows

    private func codeRow(_ info: ItemInfo) -> some View {
        DetailRow {
            VStack(alignment: .leading, spacing: 8) {
                // The code's own label starts with these words: read once.
                RowLabel("One-time code").accessibilityHidden(true)
                LiveCode(id: info.id, title: info.title, style: .detail, fetch: fetchCode,
                         onError: { error in
                             if case KlavError.Locked = error { model.lock() } else { problem = describe(error) }
                         })
            }
        } actions: {
            IconButton(icon: .copy, label: "Copy the code") { copyCode() }
        }
    }

    private func siteRow(_ url: String) -> some View {
        DetailRow {
            VStack(alignment: .leading, spacing: 5) {
                RowLabel("Site")
                Text(displayHost(url))
                    .font(.ui(16))
                    .foregroundStyle(Palette.tinta)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        } actions: {
            if let link = URL(string: url), ["https", "http"].contains(link.scheme ?? "") {
                Link("Open", destination: link)
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityLabel("Open \(displayHost(url))")
            }
        }
    }

    /// Sites an agent added (ADR 0030 §7): never filled until the person
    /// confirms them; like `klav item sites` and the extension's popup,
    /// Confirm and Remove act on all of them.
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
        FieldBlock {
            ForEach(Array(info.pendingUrls.enumerated()), id: \.offset) { index, url in
                if index > 0 { Rule() }
                DetailRow {
                    VStack(alignment: .leading, spacing: 5) {
                        RowLabel("Not confirmed")
                        // The whole URL: a look-alike must be readable.
                        Text(verbatim: url)
                            .font(.ui(15))
                            .foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } actions: {
                    EmptyView()
                }
            }
        }
        Text("Klav doesn’t fill them until you confirm them. Confirm only sites you know are this login’s.")
            .font(.ui(13, relativeTo: .footnote))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 10)
        if !model.readOnly {
            Flow(spacing: 8) {
                Button("Confirm") { settleSites(info, remove: false) }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityLabel(Text("Confirm the sites the agent added"))
                Button("Remove") { settleSites(info, remove: true) }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                    .accessibilityLabel(Text("Remove the sites the agent added"))
            }
            .disabled(settlingSites)
            .padding(.top, 12)
        }
    }

    private func referenceRow(_ info: ItemInfo) -> some View {
        DetailRow {
            VStack(alignment: .leading, spacing: 5) {
                RowLabel("For agents")
                Text(info.reference)
                    .font(.mono(12.5))
                    .foregroundStyle(Palette.gris)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } actions: {
            IconButton(icon: .copy, label: "Copy the reference for agents") { model.copy(info.reference) }
        }
    }

    private func previousValue(_ entry: PreviousPasswordInfo) async -> String? {
        if let shown = previousShown[entry.index] { return shown }
        guard let service = model.service else { return nil }
        let index = entry.index
        do {
            return try await service.run { core, _ in try core.previousPassword(id: id, index: index) }
        } catch {
            problem = describe(error)
            return nil
        }
    }

    private func togglePrevious(_ entry: PreviousPasswordInfo) {
        if previousShown[entry.index] != nil {
            previousShown[entry.index] = nil
            return
        }
        Task {
            if let value = await previousValue(entry) { previousShown[entry.index] = value }
        }
    }

    private func copyPrevious(_ entry: PreviousPasswordInfo) {
        Task {
            if let value = await previousValue(entry) { model.copy(value) }
        }
    }

    // MARK: Actions

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let service = model.service
        return { id in
            guard let service else { throw CancellationError() }
            return try await service.run { core, _ in try core.totp(id: id) }
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        do {
            detail = try await service.run { core, _ in try core.item(id: id) }
            let history = try? await service.run { core, _ in try core.passwordHistory(id: id) }
            previous = history?.entries ?? []
            pending = history
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
    }

    private func value(of field: FieldInfo) async -> String? {
        if let shown = revealed[field.name] { return shown }
        if !field.secret { return field.value }
        guard let service = model.service else { return nil }
        do {
            let name = field.name
            return try await service.run { core, _ in try core.fieldValue(id: id, field: name) }
        } catch {
            problem = describe(error)
            return nil
        }
    }

    private func toggle(_ field: FieldInfo) {
        if revealed[field.name] != nil {
            revealed[field.name] = nil
            return
        }
        Task {
            if let value = await value(of: field) { revealed[field.name] = value }
        }
    }

    private func copy(_ field: FieldInfo) {
        Task {
            if let value = await value(of: field) {
                model.copy(value)
            }
        }
    }

    private func copyCode() {
        guard let service = model.service else { return }
        Task {
            do {
                let code = try await service.run { core, _ in try core.totp(id: id) }
                model.copy(code.code)
            } catch {
                problem = describe(error)
            }
        }
    }

    private func toggleNotes() {
        if notes != nil {
            notes = nil
            return
        }
        guard let service = model.service else { return }
        Task {
            do {
                notes = try await service.run { core, _ in try core.notes(id: id) } ?? ""
            } catch {
                problem = describe(error)
            }
        }
    }

    /// Confirm: an edit of the person's with no changes, so the new version
    /// is hers and all its sites count. Remove: that same edit without them.
    private func settleSites(_ info: ItemInfo, remove: Bool) {
        guard let service = model.service else { return }
        settlingSites = true
        problem = nil
        let id = info.id
        let edit = ItemEdit(removeUrls: remove ? info.pendingUrls : [])
        Task {
            do {
                _ = try await service.run { core, _ in try core.editItem(id: id, edit: edit) }
                model.show(Toast(text: remove ? String(localized: "Removed the sites the agent added.")
                                              : String(localized: "Confirmed. Klav fills on those sites now.")))
                model.changed()
            } catch KlavError.Locked {
                model.lock()
            } catch {
                problem = describe(error)
            }
            settlingSites = false
        }
    }

    private func hideAll() {
        previousShown = [:]
        revealed = [:]
        notes = nil
    }

    private func trash() {
        guard let service = model.service else { return }
        Task {
            do {
                try await service.run { core, _ in try core.trashItem(id: id) }
                model.changed()
                model.show(Toast(text: String(localized: "Moved to the trash.")))
                dismiss()
            } catch {
                problem = describe(error)
            }
        }
    }
}

/// A row of an item's fields: what it is on the leading side and its
/// actions (show, copy, open) on the trailing one. With accessibility
/// text the actions go under the value, so the label keeps the whole
/// width and never breaks inside a word.
struct DetailRow<Main: View, Actions: View>: View {
    var alignment: VerticalAlignment = .center
    /// The block's 14 × 12 pt insets (off for the notes, outside a block).
    var padded = true
    @ViewBuilder var main: Main
    @ViewBuilder var actions: Actions

    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 10))
            : AnyLayout(HStackLayout(alignment: alignment, spacing: 8))
        layout {
            main.frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 8) { actions }
        }
        .padding(.horizontal, padded ? 14 : 0)
        .padding(.vertical, padded ? 12 : 0)
    }
}

/// The small grey name over a value ("Password", "Site"). It wraps
/// between words rather than being cut.
struct RowLabel: View {
    let text: Text
    init(_ key: LocalizedStringKey) { self.text = Text(key) }
    init(_ text: Text) { self.text = text }

    var body: some View {
        text
            .font(.ui(12, relativeTo: .caption))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// One field of an item: its name, the value (noise while secret and
/// hidden), «Show» for secrets and copy.
struct FieldRow: View {
    let field: FieldInfo
    /// The secret's value, once the person asked to see it.
    let revealed: String?
    let onToggle: () -> Void
    let onCopy: () -> Void

    var body: some View {
        DetailRow {
            VStack(alignment: .leading, spacing: 5) {
                RowLabel(Text(field.displayName))
                if field.secret {
                    MaskedValue(value: revealed)
                } else {
                    Text(field.value ?? "")
                        .font(.ui(16))
                        .foregroundStyle(Palette.tinta)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } actions: {
            if field.secret {
                Button(revealed == nil ? "Show" : "Hide", action: onToggle)
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityLabel(revealed == nil
                                        ? Text("Show \(field.displayName)") : Text("Hide \(field.displayName)"))
            }
            IconButton(icon: .copy, label: "Copy \(field.displayName)", action: onCopy)
        }
    }
}

/// One previous password: the field and when it was used, its value
/// hidden until shown, and copy. VoiceOver also hears its place in the
/// list («2 of 3»), so two changed in the same minute never read the same.
struct PreviousPasswordRow: View {
    let entry: PreviousPasswordInfo
    /// 1 is the newest.
    let position: Int
    let count: Int
    let shown: String?
    let onToggle: () -> Void
    let onCopy: () -> Void

    var body: some View {
        let name = fieldName(name: entry.field, label: entry.label)
        let date = { (ms: Int64) in Date(timeIntervalSince1970: TimeInterval(ms) / 1000) }
        let to = date(entry.toMs)
        // A password used for a single day gets the times, or two of them
        // changed the same day would read the same.
        let sameDay = entry.fromMs.map { Calendar.current.isDate(date($0), inSameDayAs: to) } ?? false
        let until = sameDay ? to.formatted(date: .abbreviated, time: .shortened) : to.formatted(date: .abbreviated, time: .omitted)
        var when: Text
        if let fromMs = entry.fromMs {
            let from = date(fromMs).formatted(date: .abbreviated, time: sameDay ? .shortened : .omitted)
            let end = sameDay ? to.formatted(date: .omitted, time: .shortened) : until
            when = Text("\(name), \(from) – \(end)")
        } else {
            when = Text("\(name), until \(until)")
        }
        // Generated for an assisted change and never confirmed: the site
        // may or may not have it.
        if entry.unconfirmed { when = Text("\(when) · generated, not confirmed") }
        let place = Int64(position), total = Int64(count)
        return DetailRow {
            VStack(alignment: .leading, spacing: 5) {
                RowLabel(when)
                    .accessibilityLabel(Text("\(when), \(place) of \(total)"))
                MaskedValue(value: shown)
            }
        } actions: {
            Button(shown == nil ? "Show" : "Hide", action: onToggle)
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .accessibilityLabel(shown == nil
                                    ? Text("Show the previous \(name) of \(until), \(place) of \(total)")
                                    : Text("Hide the previous \(name) of \(until), \(place) of \(total)"))
            IconButton(icon: .copy, label: "Copy the previous \(name) of \(until), \(place) of \(total)", action: onCopy)
        }
    }
}
