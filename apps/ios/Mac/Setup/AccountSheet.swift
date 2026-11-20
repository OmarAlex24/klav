import AppKit
import SwiftUI

/// Signing in or creating the account in the app (ADR 0027 §3). The
/// account is made in this process with `KlavCore`, which then locks; the
/// app asks `klavd` to unlock with the same password, so `klavd` is the
/// only one that keeps the vault open.
protocol AccountMaker: Sendable {
    func signIn(server: String, email: String, password: String, secretKey: String, deviceName: String) throws
    /// Returns the emergency kit as text (it holds the Secret Key).
    func signUp(server: String, email: String, password: String, deviceName: String) throws -> String
}

/// `KlavCore` on this Mac's `KLAV_HOME`, without a keystore: Touch ID is
/// `klavd`'s.
struct LiveAccounts: AccountMaker {
    let homeDir: String

    func signIn(server: String, email: String, password: String, secretKey: String, deviceName: String) throws {
        let core = try KlavCore(homeDir: homeDir)
        defer { core.lock() }
        _ = try core.signIn(server: server, email: email, password: password, secretKey: secretKey,
                            deviceName: deviceName, keystore: nil)
    }

    func signUp(server: String, email: String, password: String, deviceName: String) throws -> String {
        let core = try KlavCore(homeDir: homeDir)
        defer { core.lock() }
        return try core.signUp(server: server, email: email, password: password, deviceName: deviceName)
    }
}

struct AccountSheet: View {
    enum Mode: String, Identifiable {
        case signIn, signUp
        var id: String { rawValue }
    }

    let mode: Mode
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss

    enum Field: Hashable { case server, email, password, confirm, secretKey, device }

    @State private var server = ""
    @State private var ownServer = defaultServer() == nil
    @State private var email = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var secretKey = ""
    @State private var deviceName = AccountSheet.thisMac
    @State private var busy = false
    @State private var problem: String?
    /// The new account's kit: shown once, printed or saved as a PDF where
    /// the person chooses, dropped when the sheet closes.
    @State private var kit: String?
    @FocusState private var focus: Field?

    /// The name macOS gives this Mac (a made-up one on the sample).
    static var thisMac: String {
        #if DEBUG
        if Engines.sample { return "Ana’s MacBook Air" }
        #endif
        return Host.current().localizedName ?? "Mac"
    }

    private var chosenServer: String? {
        let typed = server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ownServer, !typed.isEmpty else { return ownServer ? nil : defaultServer() }
        return try? serverFromInput(text: typed)
    }

    private var ready: Bool {
        guard chosenServer != nil, email.contains("@"), !password.isEmpty, !busy else { return false }
        switch mode {
        case .signIn: return !secretKey.isEmpty
        case .signUp: return password == confirm
        }
    }

    var body: some View {
        Group {
            if let kit {
                KitView(text: kit) { self.kit = nil; dismiss() }
            } else {
                form
            }
        }
        .frame(width: 460)
        .background(Palette.papel)
        // The window stays on «Set up this Mac» while this sheet is open,
        // whatever klavd says meanwhile: locked between signing in and
        // its unlock, or unlocked before the kit is kept.
        .onAppear { model.accountSheetOpen = true }
        .onDisappear {
            kit = nil; password = ""; confirm = ""; secretKey = ""
            model.accountSheetOpen = false
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 14) {
            Title(mode == .signIn ? "Sign in on this Mac" : "Create your account", size: 22)
            Text(mode == .signIn
                 ? "With the details in your emergency kit."
                 : "Klav makes a Secret Key on this Mac. Together with your master password, it is the only way into your vault: nobody can reset either of them.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)

            if ownServer {
                labelled("Server") {
                    TextField("", text: $server, prompt: placeholder(String("https://klav.example.com")))
                        .textFieldStyle(.plain)
                        .focused($focus, equals: .server)
                        .inputBox(focused: focus == .server)
                }
            }
            labelled("E-mail") {
                TextField("", text: $email)
                    .textContentType(.username)
                    .textFieldStyle(.plain)
                        .focused($focus, equals: .email)
                    .inputBox(focused: focus == .email)
            }
            labelled("Master password") {
                SecureField("", text: $password)
                    .textContentType(mode == .signUp ? .newPassword : .password)
                    .textFieldStyle(.plain)
                        .focused($focus, equals: .password)
                    .inputBox(focused: focus == .password)
            }
            if mode == .signUp {
                labelled("Master password again") {
                    SecureField("", text: $confirm)
                        .textContentType(.newPassword)
                        .textFieldStyle(.plain)
                        .focused($focus, equals: .confirm)
                        .inputBox(focused: focus == .confirm)
                }
                if !confirm.isEmpty, confirm != password {
                    Text("The two passwords don’t match.").font(.ui(12.5)).foregroundStyle(Palette.rojo)
                }
            } else {
                labelled("Secret Key") {
                    SecureField("", text: $secretKey, prompt: placeholder(String("K1-XXXX-XXXX-…"), font: .mono(13)))
                        .textFieldStyle(.plain)
                        .focused($focus, equals: .secretKey)
                        .inputBox(focused: focus == .secretKey, font: .mono(13))
                }
            }
            labelled("This Mac’s name") {
                TextField("", text: $deviceName)
                    .textFieldStyle(.plain)
                        .focused($focus, equals: .device)
                    .inputBox(focused: focus == .device)
            }
            if !ownServer {
                Button("Use my own server") { ownServer = true }.buttonStyle(LinkButtonStyle())
            }
            if let problem { Notice(text: problem) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button(busy ? (mode == .signIn ? "Signing in…" : "Creating…")
                       : (mode == .signIn ? "Sign in" : "Create the account")) { Task { await submit() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .keyboardShortcut(.defaultAction)
                    .disabled(!ready)
            }
        }
        .padding(24)
        .onAppear { focus = ownServer ? .server : .email }
    }

    private func labelled<Content: View>(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(label)
            content()
        }
    }

    private func submit() async {
        guard ready, let server = chosenServer else { return }
        busy = true
        problem = nil
        let email = email.trimmingCharacters(in: .whitespaces)
        let device = deviceName.trimmingCharacters(in: .whitespaces)
        do {
            let kit = try await model.makeAccount(signUp: mode == .signUp, server: server, email: email,
                                                  password: password, secretKey: secretKey,
                                                  deviceName: device.isEmpty ? "Mac" : device)
            self.password = ""
            self.confirm = ""
            self.secretKey = ""
            if let kit { self.kit = kit } else { dismiss() }
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}

/// The new account's emergency kit: print it, or save it as a PDF from the
/// print dialog. Klav keeps no copy.
private struct KitView: View {
    let text: String
    let done: () -> Void
    @State private var saved = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Title("Your emergency kit", size: 22)
            Text("It holds your Secret Key. Print it or save it as a PDF somewhere only you can open: Klav keeps no copy, and you need it to sign in on another device.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            ScrollView {
                Text(verbatim: text)
                    .font(.mono(11.5))
                    .foregroundStyle(Palette.tinta)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
            }
            .frame(height: 230)
            .overlay(Rectangle().strokeBorder(Palette.tinta, lineWidth: 1))
            HStack {
                Button("I’ve kept it") { done() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .disabled(!saved)
                    .help(saved ? "" : String(localized: "Print it or save it as a PDF first."))
                Spacer()
                Button("Print or save as PDF…") {
                    // Cancelling the print panel does not count as kept.
                    if KitPrinter.print(text) { saved = true }
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .fixedSize()
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

/// The system's print dialog, whose PDF menu saves the kit as a file.
@MainActor
enum KitPrinter {
    /// Returns whether it was printed or saved (false when cancelled).
    @discardableResult
    static func print(_ text: String) -> Bool {
        let info = NSPrintInfo()
        info.jobDisposition = .spool
        info.topMargin = 54
        info.bottomMargin = 54
        info.leftMargin = 54
        info.rightMargin = 54
        info.isVerticallyCentered = false
        let width = info.paperSize.width - info.leftMargin - info.rightMargin
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 600))
        view.string = text
        view.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        view.textColor = .black
        view.backgroundColor = .white
        view.sizeToFit()
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.jobTitle = String(localized: "Klav emergency kit")
        operation.showsPrintPanel = true
        operation.showsProgressPanel = false
        let done = operation.run()
        view.string = ""
        return done
    }
}
