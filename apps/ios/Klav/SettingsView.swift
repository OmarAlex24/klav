import SwiftUI
import UserNotifications

/// This iPhone's settings: the account, locking, Face ID, signing out.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var preferences: Preferences
    @Environment(\.dismiss) private var dismiss

    @State private var askPassword = false
    @State private var confirmSignOut = false
    /// What signing out would lose, checked when the person asks (T138).
    /// What signing out would lose, checked when the dialog opens; `nil`
    /// with `signOutChecked`: Klav could not tell.
    @State private var signOutLoss: SignOutCheck?
    @State private var signOutChecked = false
    @State private var problem: String?
    @State private var notifications: UNAuthorizationStatus?
    @State private var generator = false
    @State private var generatorHistory = false
    @State private var importing = false
    @State private var codeSettingsFailed = false
    @State private var health = false
    @State private var kit = false
    @State private var moving = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Title("Settings", size: 22)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.horizontal, 20)
            .frame(minHeight: 64)
            .overlay(alignment: .bottom) { Rule() }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    section("Account") {
                        row("Email", model.status?.email ?? "—")
                        Rule()
                        row("Server", model.status?.server.map { serverName(server: $0) } ?? "—")
                        Rule()
                        row("This iPhone", model.status?.deviceName ?? "—")
                        if let words = model.status?.accountWords {
                            Rule()
                            row("Account words", words, pixel: true)
                        }
                    }
                    VStack(spacing: 8) {
                        Button("Print the emergency kit") { kit = true }
                            .buttonStyle(SecondaryButtonStyle())
                            .accessibilityIdentifier("settings-kit")
                        if !model.readOnly {
                            Button("Use another server") { moving = true }
                                .buttonStyle(SecondaryButtonStyle())
                                .accessibilityIdentifier("settings-move-server")
                        }
                        Button("Sign out on this iPhone") {
                            Task {
                                signOutLoss = await model.signOutCheck()
                                signOutChecked = true
                                confirmSignOut = true
                            }
                        }
                        .buttonStyle(SecondaryButtonStyle(danger: true))
                        .padding(.top, 16)
                    }
                    .padding(.top, 12)
                    // ADR 0037 §7.1: in Account, below «Sign out on this
                    // iPhone». Gone with the account (D-C).
                    if !model.readOnly {
                        DeleteAccountSection()
                            .padding(.top, 8)
                    }
                    // ADR 0051 §6.1: Klav Cloud's proxy, when there is
                    // something to say about it.
                    if !model.readOnly {
                        CloudProxySection()
                    }

                    section("Lock Klav") {
                        ForEach(AutoLock.allCases) { option in
                            Button {
                                preferences.autoLock = option
                            } label: {
                                HStack {
                                    Text(option.label).font(.ui(16)).foregroundStyle(Palette.tinta)
                                    Spacer()
                                    if preferences.autoLock == option {
                                        IconView(icon: .check).foregroundStyle(Palette.tinta)
                                    }
                                }
                                .frame(minHeight: 48)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityAddTraits(preferences.autoLock == option ? .isSelected : [])
                            if option != AutoLock.allCases.last { Rule() }
                        }
                    }

                    section("Face ID") {
                        Toggle(isOn: Binding(get: { model.biometrics?.enrolled == true && preferences.faceID },
                                             set: toggleFaceID)) {
                            Text("Unlock with Face ID").font(.ui(16)).foregroundStyle(Palette.tinta)
                        }
                        .toggleStyle(SquareToggleStyle())
                        .frame(minHeight: 52)
                        .disabled(model.biometrics?.available != true)
                    }
                    hint(Text(faceIDHint))
                    if let problem {
                        Notice(text: problem).padding(.top, 10)
                    }

                    // Both write to the vault (the generator history, a
                    // pending change): not on a deleted account's copy (D-C).
                    // Its generator history still reads, to copy what's
                    // there before deleting the copy (Q2 of the re-review).
                    section("Passwords") {
                        if model.readOnly {
                            Button("Generator history") { generatorHistory = true }
                                .buttonStyle(SecondaryButtonStyle())
                                .accessibilityIdentifier("settings-generator-history")
                        } else {
                            Button("Password generator") { generator = true }
                                .buttonStyle(SecondaryButtonStyle())
                            Button("Vault health") { health = true }
                                .buttonStyle(SecondaryButtonStyle())
                                .padding(.top, 8)
                                .accessibilityIdentifier("settings-health")
                        }
                    }

                    if !model.readOnly {
                        section("Import") {
                            Button("Import from another app") { importing = true }
                                .buttonStyle(SecondaryButtonStyle())
                                .accessibilityIdentifier("settings-import")
                        }
                    }

                    section("AutoFill") {
                        HStack(spacing: 12) {
                            Text(model.autofillEnabled == true ? "Klav is on in iOS Settings" : "Klav is off in iOS Settings")
                                .font(.ui(16)).foregroundStyle(Palette.tinta)
                            Spacer()
                            if model.autofillEnabled == false {
                                Button("Turn on") {
                                    model.offerAutofillWelcome()
                                    dismiss()
                                }
                                .buttonStyle(SecondaryButtonStyle(compact: true))
                                .accessibilityIdentifier("settings-autofill-turn-on")
                            }
                        }
                        .frame(minHeight: 52)
                        Rule()
                        Toggle(isOn: Binding(get: { preferences.quickType }, set: { on in
                            preferences.quickType = on
                            Task { await model.updateQuickType() }
                        })) {
                            Text("Suggestions on the keyboard").font(.ui(16)).foregroundStyle(Palette.tinta)
                        }
                        .toggleStyle(SquareToggleStyle())
                        .frame(minHeight: 52)
                        Rule()
                        // ADR 0035: iOS doesn't say which app was chosen, so
                        // the row only opens the place to choose it.
                        HStack(spacing: 12) {
                            Text("Set up codes in Klav").font(.ui(16)).foregroundStyle(Palette.tinta)
                            Spacer()
                            Button("Open") {
                                Task { codeSettingsFailed = !(await AppModel.openCodeSettings()) }
                            }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .accessibilityIdentifier("settings-codes")
                        }
                        .frame(minHeight: 52)
                        if codeSettingsFailed {
                            Notice(text: String(localized: "Open the iPhone’s Settings › General › AutoFill & Passwords › Set Up Codes In, and choose Klav."), tone: .info)
                                .padding(.bottom, 10)
                        }
                    }
                    hint("Suggestions show the user name and the site; the password only comes out after Face ID.")
                    hint("Choose Klav in Set Up Codes In to save the two-step verification codes you scan with the camera or open in Safari. You choose the login and confirm before anything is saved.")

                    section("Agent notifications") {
                        HStack(spacing: 12) {
                            Text(notificationsText).font(.ui(16)).foregroundStyle(Palette.tinta)
                            Spacer()
                            if notifications == .denied {
                                Button("Open Settings") {
                                    if let url = URL(string: UIApplication.openNotificationSettingsURLString) {
                                        UIApplication.shared.open(url)
                                    }
                                }
                                .buttonStyle(SecondaryButtonStyle(compact: true))
                            } else if notifications == .notDetermined {
                                Button("Turn on") {
                                    Task {
                                        await Push.prepare()
                                        notifications = await Push.status()
                                    }
                                }
                                .buttonStyle(SecondaryButtonStyle(compact: true))
                            }
                        }
                        .frame(minHeight: 52)
                    }
                    hint("Notifications carry no names or reasons: Klav asks the server for them when you open one.")

                    Text(verbatim: "Klav \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · klav-core \(coreVersion())")
                        .font(.mono(11.5))
                        .foregroundStyle(Palette.gris)
                        .padding(.top, 36)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 40)
            }
        }
        .background(Palette.papel)
        .sheet(isPresented: $generator) {
            GeneratorSheet(site: nil).environmentObject(model)
        }
        .sheet(isPresented: $generatorHistory) {
            GeneratorHistoryView(back: "Settings").environmentObject(model)
        }
        .sheet(isPresented: $importing) {
            ImportView().environmentObject(model)
        }
        .sheet(isPresented: $health) {
            HealthView().environmentObject(model)
        }
        .sheet(isPresented: $kit) {
            EmergencyKitSheet().environmentObject(model)
        }
        .sheet(isPresented: $moving) {
            MoveServerSheet(current: model.status?.server ?? "").environmentObject(model)
        }
        .onAppear { model.refreshBiometrics() }
        .task { await model.readAccountDeletion() }
        .task {
            await model.refreshAutofill()
            notifications = await Push.status()
        }
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet { password in
                try await model.enableFaceID(password: password)
            }
            .presentationDetents([.height(320)])
        }
        .confirmationDialog("Sign out on this iPhone?", isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out and delete the local copy", role: .destructive) {
                // What this dialog said, no more: one saved while it was
                // open makes Klav refuse, and the dialog comes back with
                // the new count.
                let accepted = UnsentLoss(signOutLoss).accepted
                Task {
                    switch await model.signOut(accepted: accepted) {
                    case .signedOut:
                        dismiss()
                    case .refused(let check):
                        signOutLoss = check
                        confirmSignOut = true
                    case .failed(let message):
                        problem = message
                    }
                }
            }
        } message: {
            signOutMessage
        }
    }

    /// What signing out would lose, as the check said: passkeys and
    /// generated passwords that never went up (T138; ADR 0037 Q3).
    private var signOutMessage: Text {
        if signOutChecked, signOutLoss == nil {
            return Text("Klav couldn’t check for passkeys or generated passwords that aren’t uploaded yet: if you sign out, any are lost. Connect to the internet and open Klav to upload them first.")
        }
        if signOutLoss?.lockedWithQueue == true {
            return Text("Passkeys or generated passwords saved without a connection may not be uploaded yet: if you sign out, they’re lost. Unlock Klav online to upload them first.")
        }
        guard let loss = signOutLoss, loss.unsentPasskeys > 0 || loss.unsentGenerated > 0 else {
            return Text("The encrypted copy on this iPhone is deleted. To sign in again you’ll need your emergency kit.")
        }
        var parts: [Text] = []
        if loss.unsentPasskeys > 0 {
            parts.append(Text("\(Int(loss.unsentPasskeys)) passkeys are not uploaded yet: if you sign out, they’re lost. Connect to the internet and open Klav to upload them first."))
        }
        if loss.unsentGenerated > 0 {
            parts.append(Text("\(Int(loss.unsentGenerated)) generated passwords are not uploaded yet: if you sign out, they’re lost. Copy them from the generator history, or connect to the internet and open Klav to upload them first."))
        }
        return parts.dropFirst().reduce(parts[0]) { $0 + Text(verbatim: "\n\n") + $1 }
    }

    private func hint(_ key: LocalizedStringKey) -> some View {
        hint(Text(key))
    }

    private func hint(_ text: Text) -> some View {
        text
            .font(.ui(13, relativeTo: .footnote))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 10)
    }

    private var notificationsText: String {
        switch notifications {
        case .authorized, .provisional, .ephemeral: return String(localized: "On for this iPhone")
        case .denied: return String(localized: "Off in iOS Settings")
        case .notDetermined: return String(localized: "Not turned on yet")
        default: return "—"
        }
    }

    private var faceIDHint: String {
        if model.biometrics?.available != true {
            return String(localized: "Set up Face ID in the iPhone’s Settings to use it with Klav.")
        }
        var hint = String(localized: "Klav asks for the master password every 14 days and after the iPhone restarts.")
        if model.biometrics?.enrolled == true, preferences.faceID {
            hint += " " + String(localized: "Turning it off asks for Face ID or the iPhone’s passcode.")
        }
        if Keystores.isSimulated {
            hint += " " + String(localized: "In the simulator the key isn’t in the Secure Enclave (debug builds only).")
        }
        return hint
    }

    private func toggleFaceID(_ on: Bool) {
        problem = nil
        if on {
            askPassword = true
        } else {
            // The iPhone asks for its owner first (ADR 0037 A4).
            Task {
                do {
                    try await model.disableFaceID()
                } catch KlavError.BiometryFailed {
                    problem = String(localized: "Face ID stays on in Klav: turning it off needs Face ID or the iPhone’s passcode.")
                } catch {
                    problem = describe(error)
                }
            }
        }
    }

    private func section<Content: View>(_ title: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel(title)
            VStack(spacing: 0) { content() }
        }
        .padding(.top, 30)
    }

    private func row(_ label: LocalizedStringKey, _ text: String, pixel: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
            Text(text).font(pixel ? .pixel(17, relativeTo: .body) : .ui(16)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 10)
    }
}

/// Asks for the master password to confirm a change: turning Face ID on,
/// or resuming agents on an iPhone without Face ID (ADR 0033 P2).
struct ConfirmPasswordSheet: View {
    var title: LocalizedStringKey = "Turn on Face ID"
    var message: LocalizedStringKey = "Enter your master password to keep this iPhone’s key behind Face ID."
    var action: LocalizedStringKey = "Turn on Face ID"
    let confirm: (String) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Title(title, size: 22)
            Text(message)
                .font(.ui(15)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Master password", text: $password, prompt: placeholder("Master password"))
                .textContentType(.password)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit(submit)
                .inputBox(focused: focused)
            if let problem { Notice(text: problem) }
            Button(action: submit) { Text(busy ? "Checking…" : action) }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy || password.isEmpty)
        }
        .padding(24)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.papel)
        .onAppear { focused = true }
    }

    private func submit() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        let typed = password
        password = ""
        Task {
            do {
                try await confirm(typed)
                dismiss()
            } catch KlavError.WrongCredentials {
                problem = String(localized: "The master password isn’t right.")
                busy = false
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }
}

/// «Print the emergency kit» (ADR 0028 §4): the master password first,
/// because the kit shows the Secret Key; then the kit with today's server,
/// to print. The text is dropped when the sheet closes.
struct EmergencyKitSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var text: String?
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Title("Emergency kit", size: 22)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
            }
            if let text {
                ScrollView {
                    Text(verbatim: text)
                        .font(.mono(13))
                        .foregroundStyle(Palette.tinta)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                        .overlay(Rectangle().stroke(Palette.tinta, lineWidth: 1))
                }
                Button("Print") { print(text) }
                    .buttonStyle(PrimaryButtonStyle())
                    .accessibilityIdentifier("kit-print")
            } else {
                Text("Enter your master password to see the kit. It shows your Secret Key: keep it where only you can open it.")
                    .font(.ui(15)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                SecureField("Master password", text: $password, prompt: placeholder("Master password"))
                    .textContentType(.password)
                    .focused($focused)
                    .submitLabel(.go)
                    .onSubmit(submit)
                    .inputBox(focused: focused)
                if let problem { Notice(text: problem) }
                Button(action: submit) { Text(busy ? "Checking…" : "Show the kit") }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(busy || password.isEmpty)
            }
        }
        .padding(24)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.papel)
        .onAppear { focused = true }
        .onDisappear { text = nil }
    }

    private func submit() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        let typed = password
        password = ""
        Task {
            do {
                text = try await model.emergencyKit(password: typed)
            } catch KlavError.WrongCredentials {
                problem = String(localized: "The master password isn’t right.")
            } catch {
                problem = describe(error)
            }
            busy = false
        }
    }

    private func print(_ text: String) {
        let controller = UIPrintInteractionController.shared
        let info = UIPrintInfo(dictionary: nil)
        info.outputType = .grayscale
        info.jobName = "Klav emergency kit"
        controller.printInfo = info
        let formatter = UISimpleTextPrintFormatter(text: text)
        formatter.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        formatter.perPageContentInsets = UIEdgeInsets(top: 54, left: 54, bottom: 54, right: 54)
        controller.printFormatter = formatter
        controller.present(animated: true)
    }
}

/// «Use another server» (ADR 0028 §4, also the way out when a domain is
/// down): Klav signs in there with the master password and switches only
/// if that server has this same account. `klav.dev` means the default.
struct MoveServerSheet: View {
    let current: String
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var server = ""
    @State private var password = ""
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focus: Field?

    enum Field: Hashable { case server, password }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Title("Use another server", size: 22)
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
            }
            Text("Now on \(serverName(server: current)). The new server must already have this account, with the same data.")
                .font(.ui(15)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Server", text: $server, prompt: placeholder("https://klav.your-domain.com"))
                .keyboardType(.URL)
                .textContentType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($focus, equals: .server)
                .submitLabel(.next)
                .onSubmit { focus = .password }
                .inputBox(focused: focus == .server)
            SecureField("Master password", text: $password, prompt: placeholder("Master password"))
                .textContentType(.password)
                .focused($focus, equals: .password)
                .submitLabel(.go)
                .onSubmit(submit)
                .inputBox(focused: focus == .password)
            if let problem { Notice(text: problem) }
            Button(action: submit) { Text(busy ? "Signing in there…" : "Switch server") }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy || password.isEmpty || server.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(24)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.papel)
        .onAppear { focus = .server }
    }

    private func submit() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        problem = nil
        let typed = password
        password = ""
        let target = server
        Task {
            do {
                try await model.moveServer(to: target, password: typed)
                dismiss()
            } catch KlavError.WrongCredentials {
                problem = String(localized: "The master password isn’t right.")
                busy = false
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }
}
