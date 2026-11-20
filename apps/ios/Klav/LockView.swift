import SwiftUI

/// The vault is closed: the keyhole of light full-bleed, then Face ID or
/// the master password. On unlock the light floods the field before the
/// vault appears (instant with Reduce Motion).
struct LockView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var password = ""
    @State private var usePassword = false
    @State private var busy = false
    @State private var problem: String?
    @State private var triedFaceID = false
    /// 0…1 while the keyhole floods.
    @State private var flood: Double = 0
    @FocusState private var focused: Bool

    private var faceID: Bool { model.faceIDReady && !usePassword }

    var body: some View {
        GeometryReader { geo in
            VStack(spacing: 0) {
                field
                    .frame(height: fieldHeight(geo))
                panel
                    .frame(maxHeight: .infinity, alignment: .top)
            }
            .animation(reduceMotion ? nil : .easeOut(duration: 0.22), value: focused)
        }
        .background(Palette.papel)
        .onAppear {
            if faceID {
                offerFaceID()
            } else {
                focused = true
            }
        }
        .onChange(of: model.inForeground) { _, foreground in
            // Locked while away: offer Face ID once the app is back.
            if foreground { offerFaceID() } else if !busy { triedFaceID = false }
        }
        .onChange(of: model.opening) { _, opening in
            if opening { floodField() }
        }
    }

    /// The field takes about half the screen under the status bar (as in the
    /// mockup), less while typing.
    private func fieldHeight(_ geo: GeometryProxy) -> CGFloat {
        focused ? max(130, geo.size.height * 0.22) : geo.size.height * 0.52
    }

    private var field: some View {
        DitherView(kind: .keyhole(open: flood), pixel: 4, keep: flood == 0)
            .background(Palette.marino)
            .clipped()
    }

    private var panel: some View {
        VStack(alignment: .leading, spacing: 0) {
            Wordmark(size: 22)
                .accessibilityLabel("Klav is locked")
                .accessibilityAddTraits(.isHeader)
            Text(model.lockNote ?? model.status?.email ?? String(localized: "Klav is locked"))
                .font(.ui(15, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .lineLimit(2)
                .padding(.top, 10)
            // A link from iOS waits in memory for the vault (ADR 0035 §4).
            if let pending = model.pendingCode {
                Notice(text: pending.name.map { String(localized: "Unlock Klav to save the code for \($0).") }
                       ?? String(localized: "Unlock Klav to save the code."), tone: .info)
                    // Its own height: the panel's spare room goes to the spacer.
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 16)
                    .accessibilityIdentifier("lock-pending-code")
            } else if !model.migrationLinks.isEmpty {
                Notice(text: String(localized: "Unlock Klav to import the codes from Google Authenticator."), tone: .info)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 16)
            }
            if let problem {
                Notice(text: problem).padding(.top, 16)
            }
            Spacer(minLength: 20)
            actions
        }
        .padding(.horizontal, 24)
        .padding(.top, 26)
        .padding(.bottom, 16)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private var actions: some View {
        VStack(spacing: 10) {
            if faceID {
                Button(action: unlockWithFaceID) {
                    Text(busy ? "Waiting for Face ID…" : "Unlock with Face ID")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy)
                Button("Use the master password") {
                    usePassword = true
                    focused = true
                }
                .buttonStyle(LinkButtonStyle())
            } else {
                SecureField("Master password", text: $password, prompt: placeholder("Master password"))
                    .textContentType(.password)
                    .focused($focused)
                    .submitLabel(.go)
                    .onSubmit(unlockWithPassword)
                    .inputBox(focused: focused)
                Button(action: unlockWithPassword) {
                    Text(busy ? "Checking…" : "Unlock")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy || password.isEmpty)
                if let reason = model.biometrics?.passwordRequired, model.preferences.faceID {
                    Text("Face ID asks for the password \(passwordReason(reason)).")
                        .font(.ui(13, relativeTo: .footnote))
                        .foregroundStyle(Palette.gris)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.faceIDReady {
                    Button("Use Face ID") {
                        usePassword = false
                        focused = false
                        password = ""
                    }
                    .buttonStyle(LinkButtonStyle())
                }
            }
        }
    }

    /// The threshold rises in steps (dither moves by thresholds, not
    /// smoothly) and the keyhole's light fills the field.
    private func floodField() {
        guard !reduceMotion else { return }
        focused = false
        Task {
            let steps = 12
            for step in 1...steps {
                flood = Double(step) / Double(steps)
                try? await Task.sleep(for: .milliseconds(400 / steps))
            }
        }
    }

    /// Shows the Face ID prompt by itself once per return to the app, but
    /// not right after the person locked it on purpose.
    private func offerFaceID() {
        guard model.inForeground, faceID, !busy, !triedFaceID, !model.lockedByHand else { return }
        triedFaceID = true
        unlockWithFaceID()
    }

    private func unlockWithFaceID() {
        busy = true
        problem = nil
        Task {
            do {
                try await model.unlockWithFaceID()
            } catch KlavError.BiometryFailed {
                // Cancelled or not recognised: stay here, Face ID still offered.
                busy = false
            } catch {
                problem = describe(error)
                busy = false
                usePassword = true
                model.refresh()
            }
        }
    }

    private func unlockWithPassword() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        problem = nil
        let typed = password
        password = ""
        Task {
            do {
                try await model.unlock(password: typed)
            } catch KlavError.WrongCredentials {
                problem = String(localized: "The master password isn’t right. Check it and try again.")
                busy = false
                focused = true
            } catch {
                problem = describe(error)
                busy = false
                focused = true
            }
        }
    }
}
