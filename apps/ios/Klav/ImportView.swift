import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// Where an import comes from (ADR 0024), with how to export from there.
/// `wire` is the name `klav-import` knows it by.
enum ImportSource: String, CaseIterable, Identifiable {
    case bitwarden, onePassword, google, chrome, firefox, safari, csv, authy

    var id: String { rawValue }

    var wire: String? {
        switch self {
        case .bitwarden: return "bitwarden"
        case .onePassword: return "1password"
        case .google: return "google"
        case .chrome: return "chrome"
        case .firefox: return "firefox"
        case .safari: return "safari"
        case .csv: return "csv"
        case .authy: return nil
        }
    }

    var name: String {
        switch self {
        case .bitwarden: return "Bitwarden"
        case .onePassword: return "1Password"
        case .google: return "Google Authenticator"
        case .chrome: return String(localized: "Chrome, Edge or Brave")
        case .firefox: return "Firefox"
        case .safari: return String(localized: "Safari and Passwords")
        case .csv: return String(localized: "Another app (CSV)")
        case .authy: return "Authy"
        }
    }

    var subtitle: String {
        switch self {
        case .bitwarden: return String(localized: "The .json export, with one-time codes")
        case .onePassword: return String(localized: "The .1pux export")
        case .google: return String(localized: "The QR codes of Transfer accounts")
        case .chrome: return String(localized: "The browser’s .csv export")
        case .firefox: return "logins.csv"
        case .safari: return "Passwords.csv"
        case .csv: return String(localized: "Columns title, url, username, password…")
        case .authy: return String(localized: "No export: move each code by hand")
        }
    }

    /// A site whose logo Klav ships, for the tile.
    var site: String? {
        switch self {
        case .bitwarden: return "https://bitwarden.com"
        case .onePassword: return "https://1password.com"
        case .google: return "https://google.com"
        case .firefox: return "https://firefox.com"
        default: return nil
        }
    }

    /// The export, in order. The file ones end with getting it onto the iPhone.
    var steps: [String] {
        let toPhone = String(localized: "Get the file onto this iPhone (AirDrop, or save it in iCloud Drive) and choose it below.")
        switch self {
        case .bitwarden:
            return [String(localized: "In the Bitwarden web vault, open Tools → Export vault. In the apps it’s File → Export vault, or Settings → Export vault."),
                    String(localized: "Choose the file format .json. Not “.json (Encrypted)”: Klav can’t read that one."),
                    String(localized: "Confirm with your master password. Bitwarden saves bitwarden_export_….json."),
                    toPhone]
        case .onePassword:
            return [String(localized: "Open 1Password on your computer and choose File → Export, then the account."),
                    String(localized: "Pick the 1PUX format and enter your password."),
                    String(localized: "1Password saves a file ending in .1pux."),
                    toPhone]
        case .google:
            return [String(localized: "On your phone, open Google Authenticator, open its menu and choose Transfer accounts → Export accounts."),
                    String(localized: "Select the accounts. With many, the app shows several QR codes, one after another: you need all of them."),
                    String(localized: "If Google Authenticator is on another phone, scan each QR code with this iPhone’s camera. If it’s on this iPhone, take a screenshot of each one and choose them from Photos.")]
        case .chrome:
            return [String(localized: "Chrome: open chrome://password-manager/settings. Edge: edge://settings/passwords. Brave: brave://password-manager/settings."),
                    String(localized: "Choose Export passwords (in Edge it’s under ⋯) and confirm with your computer’s password."),
                    String(localized: "The browser saves a .csv file."),
                    toPhone]
        case .firefox:
            return [String(localized: "Open about:logins in Firefox."),
                    String(localized: "Click ⋯ → Export passwords and confirm."),
                    String(localized: "Firefox saves logins.csv."),
                    toPhone]
        case .safari:
            return [String(localized: "On macOS 15 or later, open the Passwords app and choose File → Export All Passwords to File."),
                    String(localized: "On earlier versions, in Safari choose File → Export → Passwords."),
                    String(localized: "Confirm with Touch ID or your password. It saves Passwords.csv."),
                    toPhone]
        case .csv:
            return [String(localized: "Export a CSV file from the other app."),
                    String(localized: "Klav reads the columns title (or name), url, username, password, notes, totp and tags."),
                    toPhone]
        case .authy:
            return [String(localized: "Sign in to the site and open its two-factor settings."),
                    String(localized: "Choose to change the authenticator app, or turn two-factor off and on again. The site shows a new QR code and its setup key."),
                    String(localized: "Add that setup key to the site’s login in Klav as its one-time code, and type the code Klav shows to confirm."),
                    String(localized: "Only then remove the site from Authy.")]
        }
    }
}

/// What an import row's change means, for the person.
func importChange(_ wire: String) -> String {
    switch wire {
    case "password_added": return String(localized: "password added")
    case "password_replaced": return String(localized: "new password, the old one goes to its history")
    case "password_kept": return String(localized: "Klav’s password is newer, the imported one goes to its history")
    case "history_added": return String(localized: "earlier passwords kept in its history")
    case "totp_added": return String(localized: "one-time code added")
    case "totp_second": return String(localized: "a second one-time code added")
    case "urls_added": return String(localized: "sites added")
    case "notes_added": return String(localized: "notes added")
    case "fields_added": return String(localized: "fields added")
    case "tags_added": return String(localized: "tags added")
    case "renamed": return String(localized: "the title was taken")
    case "totp_item": return String(localized: "no matching login, its own one-time code item")
    case "passkey_added": return String(localized: "passkey added")
    case "passkey_kept": return String(localized: "it already has another passkey, which stays")
    case "passkey_other_site": return String(localized: "its passkey is for another site: not imported")
    default: return wire
    }
}

/// "5 new items, 1 merged into an item you have and 2 already in Klav."
func importSummary(_ p: ImportPreviewInfo) -> String {
    var parts: [String] = []
    if p.new > 0 { parts.append(String(localized: "\(Int(p.new)) new items")) }
    if p.merged > 0 { parts.append(String(localized: "\(Int(p.merged)) merged into items you have")) }
    if p.duplicates > 0 { parts.append(String(localized: "\(Int(p.duplicates)) already in Klav")) }
    guard !parts.isEmpty else { return String(localized: "Nothing new to import: it’s all in Klav already.") }
    return parts.formatted(.list(type: .and)) + "."
}

/// "Where are you coming from?": the source and how to export from it,
/// the files (or QR codes), what changes, the import, and the reminder to
/// delete the export. Nothing is written before "Import".
struct ImportView: View {
    /// Opened by iOS with Google Authenticator's `otpauth-migration://`
    /// links (ADR 0035 §5): starts at Google Authenticator with them added,
    /// and adds the next ones as they come.
    var incoming = false
    /// Closes it when it isn't a SwiftUI sheet (the links from iOS).
    var close: (() -> Void)?

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private enum Step: Equatable {
        case sources, source(ImportSource), preview, done
    }

    @State private var step: Step = .sources
    @State private var session = ImportSession()
    @State private var state: ImportStateInfo?
    @State private var names: [String] = []
    @State private var problem: String?
    @State private var busy = false
    @State private var choosingFile = false
    @State private var scanning = false
    @State private var photos: [PhotosPickerItem] = []
    @State private var pasted = ""
    @State private var codes: Set<String> = []
    @State private var shots = 0
    @State private var projects: [ProjectInfo] = []
    @State private var destination: ProjectInfo?
    @State private var preview: ImportPreviewInfo?
    @State private var result: ImportResultInfo?
    @State private var sealing = 0.0
    @FocusState private var pasting: Bool

    var body: some View {
        VStack(spacing: 0) {
            bar
            ScrollViewReader { scroller in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        switch step {
                        case .sources: sources
                        case .source(let source) where source == .authy: authy
                        case .source(let source): files(source)
                        case .preview: review
                        case .done: done
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 40)
                    .id("top")
                }
                .scrollDismissesKeyboard(.immediately)
                .onChange(of: step) { _, _ in scroller.scrollTo("top", anchor: .top) }
            }
        }
        .background(Palette.papel)
        // Opened from iOS, it covers whatever showed the toasts.
        .toastHost(model, when: incoming)
        .task {
            await loadProjects()
            await adoptIncoming()
        }
        .onChange(of: model.migrationLinks) { _, _ in Task { await adoptIncoming() } }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data], allowsMultipleSelection: true) { picked in
            switch picked {
            case .success(let urls): Task { await addFiles(urls) }
            case .failure(let error): problem = error.localizedDescription
            }
        }
        .sheet(isPresented: $scanning) {
            QRScanSheet(added: codes.count, missing: state?.missing ?? [], problem: problem) { text in
                Task { await addCode(text, name: String(localized: "QR code \(codes.count + 1)")) }
            }
        }
        .onChange(of: photos) { _, items in
            guard !items.isEmpty else { return }
            Task { await addPhotos(items) }
        }
    }

    // MARK: Bar

    private var bar: some View {
        HStack(spacing: 8) {
            if step != .sources && step != .done {
                IconButton(icon: .back, label: "Back") { back() }
            }
            Title("Import", size: 22)
            Spacer()
            Button("Close") { leave() }.buttonStyle(SecondaryButtonStyle(compact: true))
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 64)
        .overlay(alignment: .bottom) { Rule() }
    }

    private func back() {
        problem = nil
        switch step {
        case .preview:
            preview = nil
            if let source = currentSource { step = .source(source) } else { step = .sources }
        default:
            startOver()
            step = .sources
        }
    }

    @State private var currentSource: ImportSource?

    // MARK: Sources

    private var sources: some View {
        VStack(alignment: .leading, spacing: 0) {
            Title("Where are you coming from?", size: 28).padding(.top, 28)
            Text("Nothing is imported until you review it.")
                .font(.ui(15)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 10)
            VStack(spacing: 0) {
                Rule()
                ForEach(ImportSource.allCases) { source in
                    Button {
                        startOver()
                        currentSource = source
                        step = .source(source)
                    } label: {
                        HStack(spacing: 14) {
                            Tile(title: source.name, site: source.site, size: 36)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(source.name).font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                                Text(source.subtitle).font(.ui(13, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                            }
                            Spacer(minLength: 8)
                            IconView(icon: .back).foregroundStyle(Palette.cruz).scaleEffect(x: -1, y: 1)
                        }
                        .frame(minHeight: 64)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("source-\(source.rawValue)")
                    Rule()
                }
            }
            .padding(.top, 24)
            // How logins are merged is said in the review, where it happens.
        }
    }

    private var ruleText: some View {
        Text("Logins for the same site and user become one item. When their passwords differ, the newer one stays and the other goes to the item’s password history: no password is lost.")
            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Steps

    private func stepsList(_ steps: [String]) -> some View {
        VStack(spacing: 0) {
            Rule()
            ForEach(Array(steps.enumerated()), id: \.offset) { index, text in
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(verbatim: "\(index + 1)")
                        .font(.ui(12, .semibold, relativeTo: .caption))
                        .foregroundStyle(Palette.tinta)
                        .frame(width: 22, height: 22)
                        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                        .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 5 }
                    Text(text).font(.ui(15)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.vertical, 12)
                .accessibilityElement(children: .combine)
                Rule()
            }
        }
    }

    // MARK: Authy

    private var authy: some View {
        VStack(alignment: .leading, spacing: 0) {
            Title("Authy has no export", size: 28).padding(.top, 28)
            Text("Authy never offered a way to take your codes out, and its desktop apps closed in 2024. Move each code by making Klav the site’s authenticator, one site at a time:")
                .font(.ui(15)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 10)
            stepsList(ImportSource.authy.steps).padding(.top, 20)
            Text("Klav doesn’t read the file Twilio sends on a data request: its codes are encrypted with a scheme Twilio doesn’t document.")
                .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 16)
            Button("All sources") { step = .sources }
                .buttonStyle(SecondaryButtonStyle())
                .padding(.top, 28)
        }
    }

    // MARK: Files

    private func files(_ source: ImportSource) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Title(String(localized: "From \(source.name)"), size: 28).padding(.top, 28)
            SectionLabel("How to export").padding(.top, 22).padding(.bottom, 4)
            stepsList(source.steps)
            if source == .google {
                googleInputs.padding(.top, 22)
            } else {
                Button(names.isEmpty ? "Choose the file" : "Add another file") { problem = nil; choosingFile = true }
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(busy)
                    .padding(.top, 22)
                    .accessibilityIdentifier("import-choose")
            }
            if busy {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Reading…").font(.ui(14)).foregroundStyle(Palette.gris)
                }
                .padding(.top, 14)
            }
            if let problem {
                Notice(text: problem).padding(.top, 14).accessibilityIdentifier("import-problem")
            }
            if let state, !state.files.isEmpty {
                fileList(state).padding(.top, 22)
            }
            if projects.count > 1, state?.entries ?? 0 > 0 {
                destinationPicker.padding(.top, 22)
            }
            Button(action: { Task { await reviewImport() } }) { Text("Review import") }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy || (state?.entries ?? 0) == 0)
                .padding(.top, 26)
                .accessibilityIdentifier("import-review")
            if !names.isEmpty {
                Button("Start over") { startOver() }
                    .buttonStyle(LinkButtonStyle())
                    .padding(.top, 6)
            }
        }
    }

    private var googleInputs: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button("Scan with the camera") { problem = nil; scanning = true }
                .buttonStyle(PrimaryButtonStyle())
                .accessibilityIdentifier("import-scan")
            PhotosPicker(selection: $photos, maxSelectionCount: 20, matching: .images) {
                Text("Choose screenshots")
            }
            .buttonStyle(SecondaryButtonStyle())
            .accessibilityIdentifier("import-photos")
            FieldLabel("Or paste the otpauth-migration:// links, one per line").padding(.top, 10)
            TextField("Links", text: $pasted, prompt: Text(verbatim: "otpauth-migration://…").font(.mono(13)).foregroundColor(Palette.gris), axis: .vertical)
                .font(.mono(13))
                .lineLimit(3...6)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($pasting)
                .inputBox(focused: pasting)
                .accessibilityIdentifier("import-paste")
            Button("Add links") { Task { await addPasted() } }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    private func fileList(_ state: ImportStateInfo) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionLabel("Added").padding(.bottom, 4)
            ForEach(Array(state.files.enumerated()), id: \.offset) { _, file in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(file.name).font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                            .lineLimit(2)
                        Spacer(minLength: 8)
                        Text(String(localized: "\(Int(file.items)) entries"))
                            .font(.ui(13, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    }
                    Text(file.format).font(.mono(11.5)).foregroundStyle(Palette.gris)
                    ForEach(Array(file.skipped.enumerated()), id: \.offset) { _, r in
                        remark(String(localized: "\(r.at): not imported (\(r.reason))"))
                    }
                    ForEach(Array(file.notes.enumerated()), id: \.offset) { _, r in
                        remark("\(r.at): \(r.reason)")
                    }
                    if file.moreRemarks > 0 {
                        remark(String(localized: "\(Int(file.moreRemarks)) more rows skipped or shortened."))
                    }
                }
                .padding(.vertical, 10)
                .accessibilityElement(children: .combine)
                Rule()
            }
            VStack(alignment: .leading, spacing: 8) {
                ForEach(state.missing, id: \.size) { batch in
                    Notice(text: missingText(batch), tone: .info)
                }
                if state.passkeys > 0 {
                    Notice(text: String(localized: "\(Int(state.passkeys)) passkeys won’t be imported: this file doesn’t carry their keys, or they aren’t valid."), tone: .info)
                }
            }
            .padding(.top, 12)
        }
    }

    private func remark(_ text: String) -> some View {
        Text(text).font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var destinationPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel("Import into")
            Menu {
                ForEach(projects, id: \.id) { project in
                    Button { destination = project } label: { Text(verbatim: "\(project.vault) / \(project.name)") }
                }
            } label: {
                HStack {
                    Text(verbatim: destination.map { "\($0.vault) / \($0.name)" } ?? "—")
                        .font(.ui(16)).foregroundStyle(Palette.tinta)
                    Spacer()
                    IconView(icon: .back).rotationEffect(.degrees(-90)).foregroundStyle(Palette.gris)
                }
                .inputBox(focused: false)
            }
        }
    }

    // MARK: Review

    @ViewBuilder private var review: some View {
        if let preview {
            VStack(alignment: .leading, spacing: 0) {
                Title("Review before importing", size: 28).padding(.top, 28)
                Text(importSummary(preview))
                    .font(.ui(18, .medium)).tracking(-0.3).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 12)
                    .accessibilityIdentifier("import-summary")
                Text(String(localized: "Into \(preview.vault) / \(preview.project)."))
                    .font(.ui(14)).foregroundStyle(Palette.gris).padding(.top, 4)
                if preview.passkeys > 0 {
                    Notice(text: String(localized: "\(Int(preview.passkeys)) passkeys won’t be imported: this file doesn’t carry their keys, or they aren’t valid."), tone: .info)
                        .padding(.top, 14)
                }
                group("New", rows: preview.rows.filter { $0.action == "new" })
                group("Merged", rows: preview.rows.filter { $0.action == "merge" })
                group("Already in Klav", rows: preview.rows.filter { $0.action == "duplicate" })
                if preview.rowsTotal > preview.rows.count {
                    remark(String(localized: "And \(Int(preview.rowsTotal) - preview.rows.count) more.")).padding(.top, 8)
                }
                ruleText.padding(.top, 20)
                if let problem { Notice(text: problem).padding(.top, 14) }
                let count = Int(preview.new + preview.merged)
                if count == 0 {
                    Notice(text: String(localized: "Nothing new to import: it’s all in Klav already."), tone: .info)
                        .padding(.top, 24)
                } else {
                    Button(action: { Task { await apply() } }) {
                        Text(busy ? String(localized: "Importing…") : String(localized: "Import \(count) items"))
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(busy)
                    .padding(.top, 24)
                    .accessibilityIdentifier("import-apply")
                }
                Button("Back to the files") { back() }
                    .buttonStyle(LinkButtonStyle())
                    .padding(.top, 6)
            }
        }
    }

    @ViewBuilder private func group(_ title: LocalizedStringKey, rows: [ImportRowInfo]) -> some View {
        if !rows.isEmpty {
            SectionLabel(title).padding(.top, 26).padding(.bottom, 2)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                HStack(alignment: .top, spacing: 12) {
                    Tile(title: row.target, site: row.host.map { "https://\($0)" }, size: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.title).font(.ui(16, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                        let who = [row.username, row.host].compactMap { $0 }.joined(separator: " · ")
                        if !who.isEmpty {
                            Text(who).font(.ui(13, relativeTo: .subheadline)).foregroundStyle(Palette.gris).lineLimit(1)
                        }
                        let what = changesText(row)
                        if !what.isEmpty {
                            Text(what).font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.tinta)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer(minLength: 8)
                    Text(row.kind.shortName).font(.mono(11)).foregroundStyle(Palette.gris).padding(.top, 3)
                }
                .padding(.vertical, 10)
                .accessibilityElement(children: .combine)
                Rule()
            }
        }
    }

    private func changesText(_ row: ImportRowInfo) -> String {
        var parts: [String] = []
        if row.target != row.title {
            switch row.action {
            case "merge": parts.append(String(localized: "into “\(row.target)”"))
            case "duplicate": parts.append(String(localized: "same as “\(row.target)”"))
            default: parts.append(String(localized: "as “\(row.target)”"))
            }
        }
        parts += row.changes.map { change in
            // Named, so a file cannot add a site unseen (T119).
            if change == "urls_added", !row.sitesAdded.isEmpty {
                return String(localized: "sites added: \(row.sitesAdded.joined(separator: ", "))")
            }
            return importChange(change)
        }
        return parts.joined(separator: ", ")
    }

    // MARK: Done

    @ViewBuilder private var done: some View {
        if let result {
            VStack(alignment: .leading, spacing: 0) {
                DitherView(kind: .keyhole(open: sealing), pixel: 4, keep: sealing == 0)
                    .frame(height: 150)
                    .padding(.horizontal, -20)
                Title("Imported", size: 28).padding(.top, 24)
                Text(String(localized: "Created \(Int(result.created)), updated \(Int(result.updated)), into \(result.vault) / \(result.project)."))
                    .font(.ui(15)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 8)
                    .accessibilityIdentifier("import-result")
                if !result.passkeysFailed.isEmpty {
                    Notice(text: ([String(localized: "Some passkeys could not be saved; their logins were imported without them:")] + result.passkeysFailed).joined(separator: "\n"), tone: .info)
                        .padding(.top, 12)
                }
                VStack(alignment: .leading, spacing: 10) {
                    Text("Now delete the export").font(.ui(18, .semibold)).tracking(-0.5).foregroundStyle(Palette.tinta)
                        .accessibilityAddTraits(.isHeader)
                    if currentSource != .google {
                        Text("It holds your passwords in plain text. Delete it wherever you saved it (the computer, Files, AirDrop’s Downloads) and empty the trash and Recently Deleted:")
                            .font(.ui(14)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(names, id: \.self) { name in
                                Text(name).font(.mono(12)).foregroundStyle(Palette.tinta)
                            }
                        }
                    } else {
                        Text("The QR codes hold your one-time code secrets: delete their photos too, and the recently deleted ones.")
                            .font(.ui(14)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .crossCorners()
                .padding(.top, 24)
                Button("Import from somewhere else") {
                    startOver()
                    step = .sources
                }
                .buttonStyle(SecondaryButtonStyle())
                .padding(.top, 28)
                Button("Close") { leave() }
                    .buttonStyle(LinkButtonStyle())
                    .padding(.top, 6)
            }
        }
    }

    // MARK: Work

    private func leave() {
        if let close { close() } else { dismiss() }
    }

    /// Adds the `otpauth-migration://` links iOS opened Klav with, at
    /// Google Authenticator; the same link twice counts once.
    private func adoptIncoming() async {
        guard incoming, !model.migrationLinks.isEmpty else { return }
        if currentSource != .google || step == .sources || step == .done {
            startOver()
            currentSource = .google
            step = .source(.google)
        } else if step == .preview {
            // New codes change the plan: check it again.
            preview = nil
            step = .source(.google)
        }
        for link in model.migrationLinks {
            await addCode(link, name: String(localized: "QR code \(codes.count + 1)"))
        }
    }

    private func startOver() {
        session = ImportSession()
        state = nil
        names = []
        codes = []
        shots = 0
        pasted = ""
        photos = []
        problem = nil
        preview = nil
        result = nil
    }

    private func loadProjects() async {
        guard let service = model.service else { return }
        let found = (try? await service.run { core, _ in try core.projects(vaultId: nil) }) ?? []
        projects = found.sorted { ($0.vault, $0.name) < ($1.vault, $1.name) }
        destination = projects.first { $0.vault == "Personal" && $0.name == "General" } ?? projects.first
    }

    /// Reads a file or a QR code's text into the session.
    private func add(_ data: Data, name: String) async -> Bool {
        let session = session
        let from = currentSource?.wire
        do {
            let state = try await Task.detached(priority: .userInitiated) { () -> ImportStateInfo in
                try session.add(name: name, data: data, from: from)
                return session.state()
            }.value
            self.state = state
            if !names.contains(name) { names.append(name) }
            return true
        } catch {
            problem = describe(error)
            return false
        }
    }

    private func addFiles(_ urls: [URL]) async {
        busy = true
        problem = nil
        defer { busy = false }
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            guard size <= 64 << 20 else {
                problem = String(localized: "\(url.lastPathComponent) is too large to import.")
                return
            }
            guard let data = try? Data(contentsOf: url) else {
                problem = String(localized: "Couldn’t read \(url.lastPathComponent).")
                return
            }
            guard await add(data, name: url.lastPathComponent) else { return }
        }
    }

    private func addCode(_ text: String, name: String) async {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, codes.insert(text).inserted else { return }
        problem = nil
        if !(await add(Data(text.utf8), name: name)) { codes.remove(text) }
    }

    private func addPasted() async {
        let links = pasted.split(whereSeparator: \.isNewline).map(String.init)
        pasted = ""
        pasting = false
        for link in links {
            await addCode(link, name: String(localized: "Pasted link \(codes.count + 1)"))
        }
    }

    private func addPhotos(_ items: [PhotosPickerItem]) async {
        busy = true
        problem = nil
        defer {
            busy = false
            photos = []
        }
        var found = 0
        for item in items {
            guard let data = try? await item.loadTransferable(type: Data.self) else { continue }
            let messages = await Task.detached { QRReader.messages(in: data) }.value
            guard !messages.isEmpty else { continue }
            shots += 1
            let shot = shots
            for (n, text) in messages.enumerated() {
                found += 1
                let name = messages.count > 1
                    ? String(localized: "Screenshot \(shot), QR code \(n + 1)")
                    : String(localized: "Screenshot \(shot)")
                await addCode(text, name: name)
            }
        }
        if found == 0 {
            problem = String(localized: "No QR code found in those pictures. Take the screenshot with the whole QR code on screen.")
        }
    }

    private func reviewImport() async {
        guard let service = model.service else { return }
        busy = true
        problem = nil
        defer { busy = false }
        let session = session
        let vault = destination?.vault
        let project = destination?.name
        do {
            preview = try await service.run { core, _ in
                try core.importPreview(session: session, vault: vault, project: project)
            }
            step = .preview
        } catch KlavError.Locked {
            // Opened from iOS, locking takes it away and its links wait.
            model.lock()
            if !incoming { dismiss() }
        } catch {
            problem = describe(error)
        }
    }

    private func apply() async {
        guard let service = model.service, let preview else { return }
        busy = true
        problem = nil
        defer { busy = false }
        let session = session
        let vault = preview.vault
        let project = preview.project
        do {
            result = try await service.run { core, _ in
                try core.importApply(session: session, vault: vault, project: project)
            }
            model.changed()
            if incoming { model.migrationImported() }
            step = .done
            seal()
        } catch KlavError.Locked {
            // Opened from iOS, locking takes it away and its links wait.
            model.lock()
            if !incoming { dismiss() }
        } catch {
            problem = describe(error)
        }
    }

    /// The keyhole closes over the imported vault, by thresholds.
    private func seal() {
        guard !reduceMotion else {
            sealing = 0
            return
        }
        sealing = 1
        Task {
            let steps = 12
            for step in 1...steps {
                try? await Task.sleep(for: .milliseconds(700 / steps))
                sealing = 1 - Double(step) / Double(steps)
            }
        }
    }
}
