import AuthenticationServices
import SwiftUI
import UIKit

// «Set up codes in Klav» (ADR 0035): iOS opens `otpauth://` links (and
// Google Authenticator's `otpauth-migration://` batches) in Klav once the
// person picks it in Settings › General › AutoFill & Passwords › Set Up
// Codes In. The link is read by klav-core as soon as it arrives; Swift only
// holds the opaque `CodeLink`.

/// What an opened URL is for Klav (ADR 0035 §2).
enum IncomingLink: Equatable {
    /// `otpauth://…`: the «Save code» sheet.
    case code(String)
    /// `otpauth-migration://…`: the import wizard, as Google Authenticator.
    case migration(String)
    /// Anything else: not Klav's.
    case other

    init(_ url: URL) {
        switch url.scheme?.lowercased() {
        case "otpauth": self = .code(url.absoluteString)
        case "otpauth-migration": self = .migration(url.absoluteString)
        default: self = .other
        }
    }
}

/// A code link waiting for the person: only in memory (T145), until it is
/// saved, cancelled, replaced by another link or the person signs out.
struct PendingCode: Identifiable {
    let id = UUID()
    let link: CodeLink
    let info: CodeLinkInfo

    /// How the sheet and the lock screen name it: the issuer, else the
    /// account (both text of the link, cleaned by klav-core).
    var name: String? { info.issuer ?? info.account }
}

extension CodeLinkInfo {
    /// The kind of code, when it is not the usual one (6 digits, 30 s,
    /// SHA-1): «8 digits · every 60 s · SHA256».
    var unusual: String? {
        var parts: [String] = []
        if digits != 6 { parts.append(String(localized: "\(Int(digits)) digits")) }
        if period != 30 { parts.append(String(localized: "every \(Int(period)) s")) }
        if algorithm != "SHA1" { parts.append(algorithm) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}

extension CodeTarget {
    /// The login's site as the person reads it (its first confirmed host).
    var site: String? { item.confirmedUrls.first.flatMap(SiteIcons.host) }

    /// The search of «Another login»: title, user name or a site.
    func matches(_ text: String) -> Bool {
        let wanted = text.trimmingCharacters(in: .whitespaces)
        guard !wanted.isEmpty else { return false }
        let fields = [item.title, item.username ?? ""] + item.confirmedUrls
        return fields.contains { $0.localizedCaseInsensitiveContains(wanted) }
    }
}

/// The «Save code» sheet's steps.
enum CodeSheetStep: Equatable {
    case choose
    case confirm(String)
    case new
    case done(item: String, title: String, already: Bool)
}

/// Puts the sheet for a link over whatever is on screen (the vault, the
/// editor, Settings), so nothing under it is lost, and takes it away when
/// the vault locks. A SwiftUI `.sheet` can't go over another sheet.
@MainActor
final class IncomingPresenter: NSObject, UIAdaptivePresentationControllerDelegate {
    enum Kind: Equatable {
        case code(UUID)
        case migration
    }

    static let shared = IncomingPresenter()

    private weak var host: UIViewController?
    /// Which controller `host` was, also once it is gone.
    private var hostID: ObjectIdentifier?
    private(set) var shown: Kind?
    /// Bumped by every `present` and `dismiss`: an older wait stops, so two
    /// waits never put up two sheets.
    private var generation = 0
    /// Called when the person swipes the sheet away.
    var onSwipedAway: ((Kind) -> Void)?
    /// Called when UIKit took the sheet away without the person: SwiftUI
    /// dismisses what the screen under it presents to show its own alert
    /// or sheet (the «Add this site?» alert does). Present it again.
    var onLost: ((Kind) -> Void)?

    func present<V: View>(_ kind: Kind, _ view: V) {
        if shown == kind, host?.presentingViewController != nil { return }
        dismiss(animated: false)
        shown = kind
        generation += 1
        let mine = generation
        Task { await show(kind, view, generation: mine) }
    }

    func dismiss(animated: Bool = true) {
        shown = nil
        generation += 1
        if let host, host.presentingViewController != nil {
            host.dismiss(animated: animated)
        }
        host = nil
        hostID = nil
    }

    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        guard let kind = shown else { return }
        shown = nil
        host = nil
        hostID = nil
        onSwipedAway?(kind)
    }

    /// The sheet `id` left the screen. Checked a turn later, once a swipe
    /// or `dismiss` has said so: if it is still the one shown and nothing
    /// presents it, UIKit took it away.
    fileprivate func disappeared(_ id: ObjectIdentifier) {
        guard hostID == id, let kind = shown, host?.presentingViewController == nil else { return }
        host = nil
        hostID = nil
        onLost?(kind)
    }

    /// Waits for an alert or a dismissal to finish (an alert can't present
    /// a sheet), however long the person takes, then presents on the
    /// topmost screen. Stops if another link, a close or a lock came first.
    private func show<V: View>(_ kind: Kind, _ view: V, generation mine: Int) async {
        while shown == kind, generation == mine {
            if let top = Self.topmost(), !(top is UIAlertController), !top.isBeingDismissed, !top.isBeingPresented {
                let controller = IncomingHost(rootView: view)
                controller.view.backgroundColor = UIColor(Palette.papel)
                controller.presentationController?.delegate = self
                host = controller
                hostID = ObjectIdentifier(controller)
                top.present(controller, animated: true)
                return
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// The screen on top of the app's own window (not the privacy cover).
    private static func topmost() -> UIViewController? {
        let window = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.windowLevel == .normal && !$0.isHidden && $0.rootViewController != nil }
        var top = window?.rootViewController
        while let next = top?.presentedViewController { top = next }
        return top
    }
}

/// The sheet's controller: tells the presenter when it leaves the screen,
/// so a sheet UIKit took away comes back.
private final class IncomingHost<Content: View>: UIHostingController<Content> {
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        let id = ObjectIdentifier(self)
        Task { @MainActor in IncomingPresenter.shared.disappeared(id) }
    }
}

/// Saves the code of an `otpauth://` link into a login the person
/// chooses (ADR 0035 §3): the matching logins first, any other one, or a
/// new login. Nothing is written before the confirmation, and another code
/// is only replaced with «Replace».
struct SaveCodeView: View {
    let pending: PendingCode
    let close: () -> Void

    @EnvironmentObject private var model: AppModel
    @Environment(\.dynamicTypeSize) private var typeSize

    @State private var step: CodeSheetStep = .choose
    @State private var targets: [CodeTarget] = []
    @State private var items: [ItemInfo] = []
    @State private var projects: [ProjectInfo] = []
    @State private var loaded = false
    @State private var search = ""
    @State private var busy = false
    @State private var problem: String?
    // «New login»
    @State private var title = ""
    @State private var username = ""
    @State private var site = ""
    @State private var projectId: String?
    @FocusState private var focus: String?

    var body: some View {
        VStack(spacing: 0) {
            bar
            ScrollViewReader { scroller in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        switch step {
                        case .choose: choose
                        case .confirm(let id): confirm(id)
                        case .new: newLogin
                        case let .done(id, title, already): done(id: id, title: title, already: already)
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
        .tint(Palette.tinta)
        .toastHost(model)
        .task { await load() }
    }

    // MARK: Bar

    private var bar: some View {
        HStack(spacing: 8) {
            if case .confirm = step { IconButton(icon: .back, label: "Back") { back() } }
            if step == .new { IconButton(icon: .back, label: "Back") { back() } }
            Title("Save code", size: 22)
            Spacer()
            if case .done = step {
                Button("Done") { close() }.buttonStyle(SecondaryButtonStyle(compact: true))
            } else {
                Button("Cancel") { close() }.buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityIdentifier("code-cancel")
            }
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 64)
        .overlay(alignment: .bottom) { Rule() }
    }

    private func back() {
        problem = nil
        step = .choose
    }

    // MARK: What the link says

    private var linkCard: some View {
        HStack(alignment: .top, spacing: 14) {
            Tile(title: pending.name ?? "", size: 44)
            VStack(alignment: .leading, spacing: 3) {
                Text(pending.info.issuer ?? pending.info.account ?? String(localized: "One-time code"))
                    .font(.ui(22, .semibold, relativeTo: .title2))
                    .tracking(-0.9)
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                if pending.info.issuer != nil, let account = pending.info.account {
                    Text(account)
                        .font(.ui(15, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(pending.info.unusual.map { String(localized: "From the link · \($0)") } ?? String(localized: "From the link"))
                    .font(.mono(11.5))
                    .foregroundStyle(Palette.gris)
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(16)
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .crossCorners()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("code-link")
    }

    // MARK: Choose

    private var matching: [CodeTarget] { targets.filter(\.issuerMatch) }

    @ViewBuilder private var choose: some View {
        linkCard.padding(.top, 24)
        Text("Choose the login this code is for. Klav saves it only after you confirm.")
            .font(.ui(14)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 14)
        if let problem { Notice(text: problem).padding(.top, 14) }
        if loaded {
            SectionLabel("Logins for this code").padding(.top, 26).padding(.bottom, 2)
            if matching.isEmpty {
                Text(pending.name.map { String(localized: "No login matches “\($0)”. Search for it below, or save the code in a new login.") }
                     ?? String(localized: "No login matches this code. Search for it below, or save the code in a new login."))
                    .font(.ui(14)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.vertical, 10)
            }
            ForEach(matching, id: \.item.id) { target in
                row(target)
                Rule()
            }
            SectionLabel("Another login").padding(.top, 26).padding(.bottom, 8)
            HStack(spacing: 10) {
                IconView(icon: .search).foregroundStyle(Palette.gris)
                TextField("Search your logins", text: $search, prompt: placeholder("Search your logins"))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focus, equals: "search")
                    .submitLabel(.search)
                    // The results are under the keyboard: Search lowers it.
                    .onSubmit { focus = nil }
            }
            .inputBox(focused: focus == "search")
            .accessibilityIdentifier("code-search")
            let found = targets.filter { !$0.issuerMatch && $0.matches(search) }
            ForEach(found.prefix(50), id: \.item.id) { target in
                row(target)
                Rule()
            }
            if !search.trimmingCharacters(in: .whitespaces).isEmpty && found.isEmpty {
                Text("No other login matches “\(search)”.")
                    .font(.ui(14)).foregroundStyle(Palette.gris)
                    .padding(.vertical, 10)
            }
            Button("Save in a new login") { startNew() }
                .buttonStyle(SecondaryButtonStyle())
                .padding(.top, 22)
                .accessibilityIdentifier("code-new")
        } else {
            HStack(spacing: 10) {
                ProgressView()
                Text("Reading your logins…").font(.ui(14)).foregroundStyle(Palette.gris)
            }
            .padding(.top, 22)
        }
    }

    private func row(_ target: CodeTarget) -> some View {
        Button {
            problem = nil
            step = .confirm(target.item.id)
        } label: {
            HStack(spacing: 12) {
                Tile(title: target.item.title, site: target.item.confirmedUrls.first)
                VStack(alignment: .leading, spacing: 2) {
                    Text(target.item.title)
                        .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                        .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                    let who = [target.item.username, target.site].compactMap { $0 }.filter { !$0.isEmpty }
                    if !who.isEmpty {
                        Text(who.joined(separator: " · "))
                            .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                            .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                    }
                    if let state = codeStateText(target.code) {
                        Text(state).font(.mono(11.5)).foregroundStyle(target.code == .other ? Palette.rojo : Palette.gris)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                IconView(icon: .back).foregroundStyle(Palette.cruz).scaleEffect(x: -1, y: 1)
            }
            .frame(minHeight: 60)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowButtonStyle())
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("code-target-\(target.item.title)")
    }

    private func codeStateText(_ state: CodeState) -> String? {
        switch state {
        case .none: return nil
        case .other: return String(localized: "Has another code")
        case .same: return String(localized: "Has this code")
        }
    }

    // MARK: Confirm

    @ViewBuilder private func confirm(_ id: String) -> some View {
        if let target = targets.first(where: { $0.item.id == id }) {
            let login = target.item.title
            Title(confirmTitle(target), size: 28).padding(.top, 28)
            HStack(spacing: 12) {
                Tile(title: login, site: target.item.confirmedUrls.first, size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(login).font(.ui(17, .medium)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    if let user = target.item.username, !user.isEmpty {
                        Text(user).font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    }
                    Text(target.site ?? String(localized: "No site"))
                        .font(.mono(12)).foregroundStyle(Palette.gris)
                }
            }
            .padding(.top, 18)
            .accessibilityElement(children: .combine)
            VStack(alignment: .leading, spacing: 10) {
                if !target.issuerMatch, let issuer = pending.info.issuer {
                    Notice(text: target.site.map {
                        String(localized: "This link says it’s for “\(issuer)”, but \(login) is for \($0). Check that it’s the right login.")
                    } ?? String(localized: "This link says it’s for “\(issuer)”, but \(login) has no site. Check that it’s the right login."),
                    tone: .info)
                    .accessibilityIdentifier("code-issuer-warning")
                }
                switch target.code {
                case .other:
                    Notice(text: String(localized: "\(login) already has a one-time code. Replacing it removes the code Klav has for this login. Do it only if the site just gave you this new one."))
                        .accessibilityIdentifier("code-replace-warning")
                case .same:
                    Notice(text: String(localized: "\(login) already has this code. Nothing changes."), tone: .info)
                case .none:
                    EmptyView()
                }
                if !target.item.pendingUrls.isEmpty, target.code != .same {
                    Notice(text: String(localized: "Saving also confirms the sites an agent added: \(target.item.pendingUrls.joined(separator: ", ")). To drop them, use Remove on the item instead."),
                           tone: .info)
                }
                if let problem { Notice(text: problem) }
            }
            .padding(.top, 18)
            Group {
                switch target.code {
                case .other:
                    Button(action: { save(target, replace: true) }) { Text(busy ? String(localized: "Saving…") : String(localized: "Replace")) }
                        .buttonStyle(SecondaryButtonStyle(danger: true))
                        .accessibilityIdentifier("code-replace")
                case .same:
                    // Nothing to save: it only shows the code. `save_code`
                    // would write, and confirm an agent's pending sites.
                    Button(action: { showCode(target) }) { Text("Show the code") }
                        .buttonStyle(PrimaryButtonStyle())
                        .accessibilityIdentifier("code-show")
                case .none:
                    Button(action: { save(target, replace: false) }) { Text(busy ? String(localized: "Saving…") : String(localized: "Save the code")) }
                        .buttonStyle(PrimaryButtonStyle())
                        .accessibilityIdentifier("code-save")
                }
            }
            .disabled(busy)
            .padding(.top, 24)
            Button("Choose another login") { back() }
                .buttonStyle(LinkButtonStyle())
                .padding(.top, 6)
        }
    }

    private func confirmTitle(_ target: CodeTarget) -> String {
        switch target.code {
        case .other: return String(localized: "Replace the code in \(target.item.title)?")
        case .same: return target.item.title
        case .none: return String(localized: "Save the code in \(target.item.title)?")
        }
    }

    // MARK: New login

    @ViewBuilder private var newLogin: some View {
        Title("New login", size: 28).padding(.top, 28)
        Text(pending.name.map { String(localized: "For the “\($0)” code. Klav doesn’t take the site from the link. Type it so Klav can fill in the code in Safari and other apps.") }
             ?? String(localized: "Klav doesn’t take the site from the link. Type it so Klav can fill in the code in Safari and other apps."))
            .font(.ui(14)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 8)
        VStack(alignment: .leading, spacing: 18) {
            labelled("Title") {
                TextField("Title", text: $title, prompt: placeholder("GitHub, Bank, Test server…"))
                    .focused($focus, equals: "title")
                    .inputBox(focused: focus == "title")
                    .accessibilityIdentifier("code-new-title")
            }
            labelled("Username") {
                TextField("Username", text: $username, prompt: placeholder("you@example.com"))
                    .keyboardType(.emailAddress)
                    .focused($focus, equals: "username")
                    .inputBox(focused: focus == "username")
            }
            labelled("Site") {
                TextField("Site", text: $site, prompt: placeholder(String("https://github.com")))
                    .keyboardType(.URL)
                    .focused($focus, equals: "site")
                    .inputBox(focused: focus == "site")
                    .accessibilityIdentifier("code-new-site")
            }
            if projects.count > 1 {
                labelled("Where") {
                    Menu {
                        ForEach(projects, id: \.id) { project in
                            Button { projectId = project.id } label: { Text(verbatim: "\(project.vault) / \(project.name)") }
                        }
                    } label: {
                        HStack {
                            Text(verbatim: projects.first { $0.id == projectId }.map { "\($0.vault) / \($0.name)" } ?? "—")
                                .foregroundStyle(Palette.tinta)
                            Spacer()
                            Text("Change").font(.ui(14)).foregroundStyle(Palette.gris)
                        }
                        .inputBox(focused: false)
                    }
                    .accessibilityLabel("Where to save it")
                }
            }
            if titleTaken(title, in: projectId, items: items) {
                Notice(text: String(localized: "There’s already an item called “\(title.trimmingCharacters(in: .whitespaces))” there. Choose another title."))
            }
            if let problem { Notice(text: problem) }
            Button(action: saveNew) { Text(busy ? String(localized: "Saving…") : String(localized: "Save the code")) }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy || title.trimmingCharacters(in: .whitespaces).isEmpty || titleTaken(title, in: projectId, items: items))
                .accessibilityIdentifier("code-new-save")
        }
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .padding(.top, 22)
    }

    private func labelled<Content: View>(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(label)
            content()
        }
    }

    private func startNew() {
        problem = nil
        if title.isEmpty { title = pending.info.issuer ?? pending.info.account ?? "" }
        if username.isEmpty { username = pending.info.account ?? "" }
        step = .new
    }

    // MARK: Done

    @ViewBuilder private func done(id: String, title: String, already: Bool) -> some View {
        Title(already ? String(localized: "\(title) already has this code") : String(localized: "Code saved in \(title)"), size: 28)
            .padding(.top, 28)
            .accessibilityIdentifier("code-done")
        Text("If the site asks for a code to finish turning on two-step verification, enter this one.")
            .font(.ui(15)).foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 8)
        LiveCode(id: id, title: title, style: .detail, fetch: fetchCode,
                 onError: { error in if case KlavError.Locked = error { model.lock() } },
                 onCopy: { model.copy($0) })
            .padding(.vertical, 22)
        Text("Tap the code to copy it.")
            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
        Button("Done") { close() }
            .buttonStyle(PrimaryButtonStyle())
            .padding(.top, 24)
    }

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let service = model.service
        return { id in
            guard let service else { throw CancellationError() }
            return try await service.run { core, _ in try core.totp(id: id) }
        }
    }

    // MARK: Work

    private func load() async {
        guard let service = model.service else { return }
        let link = pending.link
        do {
            let (found, all, list) = try await service.run { core, _ in
                (try core.codeTargets(link: link), try core.items(query: ItemQuery()), try core.projects(vaultId: nil))
            }
            targets = found
            items = all
            projects = list.sorted { ($0.vault, $0.name) < ($1.vault, $1.name) }
            if projectId == nil {
                projectId = (projects.first { $0.vault == "Personal" && $0.name == "General" } ?? projects.first)?.id
            }
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }

    private func save(_ target: CodeTarget, replace: Bool) {
        guard let service = model.service, !busy else { return }
        busy = true
        problem = nil
        let link = pending.link
        let id = target.item.id
        Task {
            defer { busy = false }
            do {
                let outcome = try await service.run { core, _ in try core.saveCode(link: link, id: id, replace: replace) }
                switch outcome {
                case .saved(let item):
                    model.changed()
                    model.codeSaved(pending.id)
                    step = .done(item: item.id, title: item.title, already: false)
                case .alreadyThere(let item):
                    model.codeSaved(pending.id)
                    step = .done(item: item.id, title: item.title, already: true)
                case .needsReplace:
                    // It gained a code since the list was read: ask again.
                    await load()
                    problem = String(localized: "\(target.item.title) now has a code. Check it before you replace it.")
                }
            } catch KlavError.Locked {
                model.lock()
            } catch KlavError.Conflict {
                await model.sync(force: true)
                await load()
                problem = String(localized: "\(target.item.title) changed on another device. Check it and try again.")
            } catch {
                problem = describe(error)
            }
        }
    }

    /// The login already has this code: nothing is written, the sheet only
    /// shows it.
    private func showCode(_ target: CodeTarget) {
        problem = nil
        model.codeSaved(pending.id)
        step = .done(item: target.item.id, title: target.item.title, already: true)
    }

    private func saveNew() {
        guard let service = model.service, !busy else { return }
        focus = nil
        busy = true
        problem = nil
        let link = pending.link
        let typedSite = site.trimmingCharacters(in: .whitespacesAndNewlines)
        let project = projects.first { $0.id == projectId }
        let login = NewCodeLogin(
            title: title.trimmingCharacters(in: .whitespaces),
            username: username.trimmingCharacters(in: .whitespaces),
            site: typedSite.isEmpty ? nil : (typedSite.contains("://") ? typedSite : "https://" + typedSite),
            vaultId: project?.vaultId, projectId: project?.id)
        Task {
            defer { busy = false }
            do {
                let item = try await service.run { core, _ in try core.saveCodeNew(link: link, login: login) }
                model.changed()
                model.codeSaved(pending.id)
                step = .done(item: item.id, title: item.title, already: false)
            } catch KlavError.Locked {
                model.lock()
            } catch let error as KlavError {
                // The title may have been taken meanwhile (a sync):
                // klav-client's message speaks of the CLI, so the sheet
                // shows its own notice for a taken title (same rule) and
                // turns «Save» off, instead of that message.
                if let all = try? await service.run({ core, _ in try core.items(query: ItemQuery()) }) {
                    items = all
                }
                problem = titleTaken(login.title, in: login.projectId, items: items) ? nil : describe(error)
            } catch {
                problem = describe(error)
            }
        }
    }
}

extension AppModel {
    /// Opens Settings › General › AutoFill & Passwords › Set Up Codes In.
    static func openCodeSettings() async -> Bool {
        do {
            try await ASSettingsHelper.openVerificationCodeAppSettings()
            return true
        } catch {
            appLog.error("codes: settings did not open: \(error.localizedDescription, privacy: .private)")
            return false
        }
    }
}
