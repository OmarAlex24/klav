import SwiftUI
import UIKit

/// First run (or after signing out): the emergency kit. The server is
/// klav.dev unless the person opens «Use my own server» (ADR 0028 §3).
struct SignInView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var preferences: Preferences

    enum Field: Hashable { case server, email, password, secretKey, device }

    @State private var server = ""
    /// «Use my own server» is open. Always open when there is no default
    /// server (`KLAV_NO_DEFAULT_SERVER`, the tests).
    @State private var ownServer = defaultServer() == nil
    @State private var email = ""
    @State private var password = ""
    @State private var secretKey = ""
    @State private var deviceName = UIDevice.current.name
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focus: Field?

    /// The server to sign in to: the default one, or what the person
    /// typed (`klav.dev` and old URLs of klav.dev mean the default).
    private var chosenServer: String? {
        let typed = server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ownServer, !typed.isEmpty else { return ownServer ? nil : defaultServer() }
        return try? serverFromInput(text: typed)
    }

    private var ready: Bool {
        chosenServer != nil && email.contains("@")
            && !password.isEmpty && !secretKey.isEmpty && !busy
    }

    /// «Your account lives on klav.dev», or on the host typed.
    private var livesOn: String {
        guard let chosen = chosenServer else {
            return String(localized: "Your account lives on the server you type.")
        }
        return String(localized: "Your account lives on \(serverName(server: chosen)).")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                DitherView(kind: .keyhole(open: 0), pixel: 4)
                    .background(Palette.marino)
                    .frame(height: focus == nil ? 190 : 0)
                    .clipped()
                    .padding(.horizontal, -24)
                    .accessibilityHidden(true)
                Wordmark(size: 20)
                    .padding(.top, 26)
                Title("Sign in on this iPhone")
                    .padding(.top, 18)
                Text("With the details in your emergency kit.")
                    .font(.ui(15, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .padding(.top, 6)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 16) {
                    labelled("Email") {
                        TextField("Email", text: $email, prompt: placeholder("you@example.com"))
                            .keyboardType(.emailAddress)
                            .textContentType(.username)
                            .focused($focus, equals: .email)
                            .submitLabel(.next)
                            .inputBox(focused: focus == .email)
                    }
                    labelled("Master password") {
                        SecureField("Master password", text: $password, prompt: placeholder(String()))
                            .textContentType(.password)
                            .focused($focus, equals: .password)
                            .submitLabel(.next)
                            .inputBox(focused: focus == .password)
                    }
                    labelled("Secret Key") {
                        TextField("Secret Key", text: $secretKey, prompt: placeholder(String("K1-XXXX-XXXX-…"), font: .mono(15, relativeTo: .body)))
                            .textInputAutocapitalization(.characters)
                            .focused($focus, equals: .secretKey)
                            .submitLabel(.next)
                            .inputBox(focused: focus == .secretKey, font: .mono(15, relativeTo: .body))
                    }
                    labelled("This iPhone’s name") {
                        TextField("This iPhone’s name", text: $deviceName, prompt: placeholder(String("iPhone")))
                            .focused($focus, equals: .device)
                            .submitLabel(ownServer ? .next : .go)
                            .inputBox(focused: focus == .device)
                    }
                    if ownServer {
                        labelled("Server") {
                            TextField("Server", text: $server, prompt: placeholder("https://klav.your-domain.com"))
                                .keyboardType(.URL)
                                .textContentType(.URL)
                                .focused($focus, equals: .server)
                                .submitLabel(.go)
                                .inputBox(focused: focus == .server)
                        }
                        .accessibilityIdentifier("signin-server")
                    } else {
                        Button {
                            ownServer = true
                            focus = .server
                        } label: {
                            Text("Use my own server")
                                .font(.ui(15, relativeTo: .subheadline))
                                .underline()
                                .foregroundStyle(Palette.tinta)
                                .frame(minHeight: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("signin-own-server")
                    }
                }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(.top, 26)
                .onSubmit(next)

                if let problem {
                    Notice(text: problem).padding(.top, 18)
                }

                Button(action: submit) {
                    Text(busy ? "Opening the vault…" : "Sign in")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!ready)
                .padding(.top, 24)

                Text(verbatim: livesOn + " " + String(localized: "The master password and the Secret Key never leave this iPhone. The server only keeps encrypted data."))
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
                    .padding(.top, 14)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.papel)
        .scrollDismissesKeyboard(.interactively)
        .animation(.easeOut(duration: 0.2), value: focus == nil)
        .onAppear {
            // The last one used, when it was not klav.dev.
            let last = preferences.lastServer
            if server.isEmpty, !last.isEmpty, serverName(server: last) != "klav.dev" {
                server = last
                ownServer = true
            }
        }
    }

    private func labelled<Content: View>(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            FieldLabel(label)
            content()
        }
    }

    private func next() {
        switch focus {
        case .email: focus = .password
        case .password: focus = .secretKey
        case .secretKey: focus = .device
        case .device where ownServer: focus = .server
        default:
            focus = nil
            if ready { submit() }
        }
    }

    private func submit() {
        guard ready else { return }
        focus = nil
        busy = true
        problem = nil
        guard let server = chosenServer else { return }
        let (email, password, secretKey) = (email.trimmingCharacters(in: .whitespaces), password, secretKey)
        let device = deviceName.trimmingCharacters(in: .whitespaces).isEmpty ? "iPhone" : deviceName
        Task {
            do {
                try await model.signIn(server: server, email: email, password: password,
                                       secretKey: secretKey, deviceName: device)
            } catch {
                problem = describe(error)
                busy = false
            }
            self.password = ""
        }
    }
}
