import SwiftUI

// Deleting the account from the app (ADR 0037 §7). The person asks with
// Face ID (where Klav uses it) and the master password; the server deletes
// the account 7 days later, and until then any device cancels it. Nothing
// here deletes this iPhone's copy except «Delete this iPhone’s copy».

/// Settings › Account: «Delete my account», or the deletion in progress
/// with «Cancel the deletion» (§7.1, §7.4).
struct DeleteAccountSection: View {
    @EnvironmentObject private var model: AppModel
    @State private var asking = false
    @State private var checking = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let deletion = model.accountDeletion {
                DeletionPending(deletion: deletion)
            } else {
                Button(checking ? String(localized: "Checking…") : String(localized: "Delete my account")) {
                    check()
                }
                .buttonStyle(SecondaryButtonStyle(danger: true))
                .disabled(checking)
                .accessibilityIdentifier("settings-delete-account")
            }
            if let problem { Notice(text: problem) }
        }
        .sheet(isPresented: $asking) {
            DeleteAccountSheet().environmentObject(model)
        }
    }

    /// The server must be able to, before Face ID or the password (§4).
    private func check() {
        problem = nil
        checking = true
        Task {
            defer { checking = false }
            do {
                if try await model.deletionSupported() {
                    asking = true
                } else {
                    problem = String(localized: "This server can’t delete accounts from the app. Ask whoever runs it.")
                }
            } catch {
                problem = describe(error)
            }
        }
    }
}

/// The deletion in progress: when, from where, and «Cancel the deletion»
/// (§7.4). In Settings › Account.
struct DeletionPending: View {
    let deletion: AccountDeletionInfo
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(verbatim: deletionHeadline(deletion))
                .font(.ui(17, .medium)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text(deletionDue(deletion)
                 ? String(localized: "The date has passed. Klav checks with the server when it connects.")
                 : String(localized: "You asked from \(deletion.deviceName) on \(deletionDay(deletion.requestedAt)). Until then Klav keeps working, except for your agents."))
                .font(.ui(15)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            CancelDeletionButton(problem: $problem, identifier: "settings-cancel-deletion", compact: false)
            if let problem { Notice(text: problem) }
        }
        .accessibilityIdentifier("settings-deletion-pending")
    }
}

/// Above the vault while the deletion is pending (§7.4).
struct DeletionBanner: View {
    @EnvironmentObject private var model: AppModel
    @State private var problem: String?

    var body: some View {
        if let deletion = model.accountDeletion, !model.readOnly {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 0) {
                    Rectangle().fill(Palette.rojo).frame(width: 2)
                    VStack(alignment: .leading, spacing: 10) {
                        Text(verbatim: deletionHeadline(deletion))
                            .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                        if deletionDue(deletion) {
                            Text("The date has passed. Klav checks with the server when it connects.")
                                .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        CancelDeletionButton(problem: $problem, identifier: "home-cancel-deletion", compact: true)
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(Palette.niebla)
                if let problem { Notice(text: problem) }
            }
            .padding(.top, 12)
        }
    }
}

/// «Cancel the deletion»: it brings the agents back, so it asks what
/// resuming them asks (ADR 0037 A2): Face ID, or the master password
/// without it or when the person chooses it.
struct CancelDeletionButton: View {
    @EnvironmentObject private var model: AppModel
    @Binding var problem: String?
    let identifier: String
    let compact: Bool
    @State private var busy = false
    @State private var askPassword = false

    var body: some View {
        Group {
            if compact {
                Button(busy ? String(localized: "Checking…") : String(localized: "Cancel the deletion")) {
                    Task { await cancel() }
                }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            } else {
                Button(busy ? String(localized: "Checking…") : String(localized: "Cancel the deletion")) {
                    Task { await cancel() }
                }
                .buttonStyle(PrimaryButtonStyle())
            }
        }
        .disabled(busy)
        .accessibilityIdentifier(identifier)
        .sheet(isPresented: $askPassword) {
            ConfirmPasswordSheet(title: "Cancel the deletion",
                                 message: "Enter your master password to cancel the deletion and let your agents use Klav again.",
                                 action: "Cancel the deletion") { password in
                try await model.cancelAccountDeletion(password: password)
            }
            .presentationDetents([.height(340)])
        }
    }

    private func cancel() async {
        busy = true
        problem = nil
        do {
            if try await model.cancelAccountDeletion() == .needsPassword { askPassword = true }
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}

/// The two confirmations (§7.2, §7.3): what gets deleted, then the master
/// password. Face ID, where Klav uses it, comes up when the person taps
/// «Delete my account», before the password is checked.
struct DeleteAccountSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var step = Step.what
    @State private var password = ""
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focused: Bool

    enum Step { case what, password }

    /// Seven days from now, as the server will count them.
    private var deleteDay: String {
        deletionDay(Int64(Date().addingTimeInterval(7 * 24 * 3600).timeIntervalSince1970 * 1000))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Title("Delete your account?", size: 22)
                switch step {
                case .what: what
                case .password: passwordStep
                }
            }
            .padding(24)
        }
        .background(Palette.papel)
        .interactiveDismissDisabled(busy)
    }

    private var what: some View {
        VStack(alignment: .leading, spacing: 14) {
            paragraph("Klav deletes everything your account has on the server: your vaults with their items, versions and files, your devices, your agents and the audit log.")
            paragraph("It’s deleted on \(deleteDay). Until then you can cancel it from any of your devices. Your agents stop working now.")
            paragraph("Klav can’t export your vault yet: if you want to keep something, copy it first.")
            paragraph("Not deleted: the copy on your devices until you delete it, your emergency kit, and anything you copied out of Klav.")
            Button("Continue") {
                step = .password
                focused = true
            }
            .buttonStyle(SecondaryButtonStyle(danger: true))
            .padding(.top, 8)
            .accessibilityIdentifier("delete-account-continue")
            Button("Cancel") { dismiss() }
                .buttonStyle(SecondaryButtonStyle())
        }
    }

    private var passwordStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            paragraph("Enter your master password to delete the account \(model.status?.email ?? "").")
            SecureField("Master password", text: $password, prompt: placeholder("Master password"))
                .textContentType(.password)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit(submit)
                .inputBox(focused: focused)
                .accessibilityIdentifier("delete-account-password")
            if let problem { Notice(text: problem) }
            Button(action: submit) { Text(busy ? "Checking…" : "Delete my account") }
                .buttonStyle(SecondaryButtonStyle(danger: true))
                .disabled(busy || password.isEmpty)
                .accessibilityIdentifier("delete-account-confirm")
            Button("Cancel") { dismiss() }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(busy)
        }
    }

    /// Face ID can't confirm. Still set up, the deletion waits for it: the
    /// password alone never asks here (T162). Gone (the faces changed and
    /// `klav-ffi` forgot it), Klav no longer uses it, as at the unlock, and
    /// the password asks again (D-D).
    private func faceIDProblem() -> String {
        model.refreshBiometrics()
        if model.biometrics?.enrolled == false {
            return String(localized: "Face ID changed on this iPhone, so Klav stopped using it here. Enter the master password again to delete the account.")
        }
        return String(localized: "Face ID isn’t available right now. Klav uses it on this iPhone, so deleting the account needs it. If Face ID is locked, unlock the iPhone with its passcode and try again. You can also delete the account from another of your devices, or turn off Face ID for Klav in Settings (the iPhone asks for its passcode).")
    }

    private func paragraph(_ key: LocalizedStringKey) -> some View {
        Text(key)
            .font(.ui(15)).foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func submit() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        problem = nil
        let typed = password
        password = ""
        Task {
            do {
                try await model.requestAccountDeletion(password: typed)
                dismiss()
            } catch KlavError.WrongCredentials {
                problem = String(localized: "The master password isn’t right.")
                busy = false
            } catch KlavError.BiometryUnavailable {
                problem = faceIDProblem()
                busy = false
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }
}

/// After the deletion (§7.6, D-C): a fixed notice above the vault, which
/// stays readable: search and copy work, nothing edits or syncs.
struct DeletedNotice: View {
    var body: some View {
        HStack(spacing: 0) {
            Rectangle().fill(Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 2) {
                Text("Klav deleted your account")
                    .font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
                    .accessibilityAddTraits(.isHeader)
                Text("Read-only: you can search and copy, but not edit or sync.")
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            Spacer(minLength: 0)
        }
        // Outside the scroll view the stripe would take every point the
        // screen offers: the band keeps the height of its text.
        .fixedSize(horizontal: false, vertical: true)
        .background(Palette.niebla)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("deleted-notice")
    }
}

/// Under the notice, at the top of the vault (§7.6): what happened, the
/// emergency kit, and «Delete this iPhone’s copy», one more button and
/// never the only way out (D-C). What never went up (generated passwords,
/// passkeys saved offline) is only on this iPhone: Klav refuses while any
/// waits, says how many, opens the generator history to copy them, and
/// offers «Delete anyway» apart (Q3 of the re-review).
struct DeletedAccountCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var deleting = false
    @State private var confirm = false
    @State private var confirmAnyway = false
    /// What would be lost, once the check found something.
    @State private var unsent: UnsentLoss?
    @State private var history = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("On \(deletionDay(model.deletedAt ?? 0)), everything in \(model.status?.email ?? "") was deleted from the server. This iPhone still keeps an encrypted copy.")
                .font(.ui(15)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text("Destroy your emergency kit too: with it and your password, any leftover copy opens.")
                .font(.ui(15)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if let problem { Notice(text: problem) }
            if let unsent {
                UnsentNotice(loss: unsent)
                HStack(spacing: 10) {
                    if unsent.mayHoldGenerated {
                        Button("Generator history") { history = true }
                            .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                            .accessibilityIdentifier("deleted-generator-history")
                    }
                    Button("Delete anyway") { confirmAnyway = true }
                        .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                        .disabled(deleting)
                        .accessibilityIdentifier("deleted-delete-anyway")
                }
            } else {
                Button("Delete this iPhone’s copy") { check() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(deleting)
                    .accessibilityIdentifier("deleted-delete-copy")
            }
        }
        .padding(.top, 14)
        .confirmationDialog("Delete this iPhone’s copy?", isPresented: $confirm, titleVisibility: .visible) {
            Button("Delete this iPhone’s copy", role: .destructive) { deleteCopy(.nothing) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Klav can’t export your vault yet: what you don’t copy elsewhere first is lost.")
        }
        .confirmationDialog("Delete this iPhone’s copy anyway?", isPresented: $confirmAnyway, titleVisibility: .visible) {
            Button("Delete anyway", role: .destructive) { deleteCopy(.unknown) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("What never reached your account goes with it, and so does everything you haven’t copied elsewhere.")
        }
        .sheet(isPresented: $history) {
            GeneratorHistoryView(back: "Back").environmentObject(model)
        }
    }

    /// Counts what never went up first: nothing, and the usual
    /// confirmation; something, and the refusal with its count.
    private func check() {
        deleting = true
        problem = nil
        Task {
            let loss = UnsentLoss(await model.signOutCheck())
            deleting = false
            if loss == .nothing {
                confirm = true
            } else {
                unsent = loss
            }
        }
    }

    /// `.nothing`: what the confirmation said; Klav refuses if something
    /// waits by now, and the card shows it. `.unknown`: «Delete anyway».
    private func deleteCopy(_ accepted: AcceptedLoss) {
        deleting = true
        problem = nil
        Task {
            switch await model.signOut(accepted: accepted) {
            case .signedOut:
                break
            case .refused(let check):
                let loss = UnsentLoss(check)
                unsent = loss == .nothing ? .unknown : loss
            case .failed(let message):
                problem = message
            }
            deleting = false
        }
    }
}

/// What «Delete this iPhone’s copy» would lose, in the card.
struct UnsentNotice: View {
    let loss: UnsentLoss

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            switch loss {
            case .counted(let generated, let passkeys):
                if generated > 0 {
                    line(Text("\(Int(generated)) generated passwords never reached your account: they’re only on this iPhone. Copy them somewhere else before you delete this copy."))
                }
                if passkeys > 0 {
                    line(Text("\(Int(passkeys)) passkeys saved without a connection never reached your account: they’re lost with this copy."))
                }
            case .unknown:
                line(Text("Klav couldn’t check for generated passwords or passkeys that never reached your account: if you delete this copy, any are lost."))
            case .nothing:
                EmptyView()
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("deleted-unsent")
    }

    private func line(_ text: Text) -> some View {
        text
            .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
    }
}
