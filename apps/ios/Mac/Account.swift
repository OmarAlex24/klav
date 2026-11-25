import AppKit
import SwiftUI

// Deleting the account from the Mac app (ADR 0037 §4, §7): Settings (⌘,)
// › Account. The request runs in this process through `DaemonEngine`:
// `klavd` only confirms Touch ID where it is set up, and never sees the
// password (T164). After the deletion the vault stays, read-only, until
// «Delete this Mac’s copy» (T165, D-C).

/// Settings › Account: the account, and «Delete my account» or the
/// deletion in progress.
struct AccountSettingsView: View {
    @EnvironmentObject private var model: MacModel
    @State private var checking = false
    @State private var asking = false
    @State private var problem: String?
    /// Canceled from here: said under the button until Settings closes.
    @State private var said: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if model.phase == .signedOut {
                // Nothing to delete without an account.
                Text("This Mac doesn’t have an account yet.")
                    .font(.ui(14)).foregroundStyle(Palette.gris)
                    .accessibilityIdentifier("settings-no-account")
            } else {
                account
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(width: 520, alignment: .topLeading)
        .frame(minHeight: 360, alignment: .top)
        .background(Palette.papel)
        .onDisappear { said = nil }
        #if DEBUG
        .onAppear {
            if UserDefaults.standard.string(forKey: "KlavSheet") == "deleteAccount" { asking = true }
        }
        #endif
        .sheet(isPresented: $asking) {
            MacDeleteAccountSheet().environmentObject(model)
        }
    }

    @ViewBuilder private var account: some View {
        VStack(alignment: .leading, spacing: 4) {
            FieldLabel("Email")
            Text(verbatim: model.info?.email ?? "")
                .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
        }
        Rule()
        if model.accountDeleted {
            DeletedAccountContent()
        } else if let deletion = model.accountDeletion {
            DeletionPendingBlock(deletion: deletion) { canceled in
                said = canceled
                    ? String(localized: "The deletion was canceled. Your agents work again.")
                    : String(localized: "The deletion was already canceled.")
            }
        } else {
            Button(checking ? String(localized: "Checking…") : String(localized: "Delete my account")) {
                check()
            }
            .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
            .disabled(checking || model.phase == .noDaemon)
            .accessibilityIdentifier("settings-delete-account")
            if let said { Notice(text: said, tone: .info) }
        }
        if let problem { Notice(text: problem) }
    }

    /// The server must be able to, before Touch ID or the password (§4).
    private func check() {
        problem = nil
        said = nil
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

/// What «Cancel the deletion» says when it can't: a locked `klavd` can't
/// cancel, and unlocking is the way forward.
func cancelDeletionProblem(_ error: Error) -> String {
    if let e = error as? KlavError, case .Locked = e { return String(localized: "Unlock Klav to cancel.") }
    return describe(error)
}

/// The deletion in progress (§7.4): when, from where, and «Cancel the
/// deletion», which asks for Touch ID or the master password (A2).
struct DeletionPendingBlock: View {
    let deletion: AccountDeletionInfo
    var canceled: (Bool) -> Void = { _ in }
    @EnvironmentObject private var model: MacModel
    @State private var canceling = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(verbatim: deletionHeadline(deletion))
                .font(.ui(15, .medium)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text(deletionDue(deletion)
                 ? String(localized: "The date has passed. Klav checks with the server when it connects.")
                 : String(localized: "You asked from \(deletion.deviceName) on \(deletionDay(deletion.requestedAt)). Until then Klav keeps working, except for your agents."))
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Button(canceling ? model.waitingForPresence : String(localized: "Cancel the deletion")) {
                cancel()
            }
            .buttonStyle(PrimaryButtonStyle(compact: true))
            .fixedSize()
            .disabled(canceling)
            .padding(.top, 4)
            .accessibilityIdentifier("settings-cancel-deletion")
            if let problem { Notice(text: problem) }
        }
    }

    private func cancel() {
        canceling = true
        problem = nil
        Task {
            defer { canceling = false }
            do {
                try await model.cancelAccountDeletion { canceled($0) }
            } catch {
                problem = cancelDeletionProblem(error)
            }
        }
    }
}

/// Above the window's content while the deletion is pending (§7.4).
struct DeletionBand: View {
    @EnvironmentObject private var model: MacModel
    @State private var canceling = false
    @State private var problem: String?

    var body: some View {
        if let deletion = model.accountDeletion {
            HStack(spacing: 0) {
                Rectangle().fill(Palette.rojo).frame(width: 2)
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: deletionHeadline(deletion))
                            .font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                        if deletionDue(deletion) {
                            Text("The date has passed. Klav checks with the server when it connects.")
                                .font(.ui(12)).foregroundStyle(Palette.gris)
                        }
                    }
                    Spacer(minLength: 8)
                    if let problem {
                        Text(verbatim: problem)
                            .font(.ui(12)).foregroundStyle(Palette.rojo)
                            .lineLimit(2)
                    }
                    Button(canceling ? model.waitingForPresence : String(localized: "Cancel the deletion")) {
                        cancel()
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .disabled(canceling)
                    .accessibilityIdentifier("home-cancel-deletion")
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
            }
            .fixedSize(horizontal: false, vertical: true)
            .background(Palette.niebla)
            .accessibilityElement(children: .contain)
        }
    }

    private func cancel() {
        canceling = true
        problem = nil
        Task {
            defer { canceling = false }
            do {
                try await model.cancelAccountDeletion()
            } catch {
                problem = cancelDeletionProblem(error)
            }
        }
    }
}

/// Above the vault once Klav deleted the account (§7.6, D-C): fixed, with
/// «Delete this Mac’s copy», one more button and never the only way out.
struct DeletedBand: View {
    @EnvironmentObject private var model: MacModel
    @State private var problem: String?

    var body: some View {
        if model.accountDeleted {
            HStack(spacing: 0) {
                Rectangle().fill(Palette.rojo).frame(width: 2)
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Klav deleted your account")
                            .font(.ui(13.5, .semibold)).foregroundStyle(Palette.tinta)
                            .accessibilityAddTraits(.isHeader)
                        Text("Read-only: you can search and copy, but not edit or sync.")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                    }
                    Spacer(minLength: 8)
                    if let problem {
                        Text(verbatim: problem)
                            .font(.ui(12)).foregroundStyle(Palette.rojo)
                            .lineLimit(2)
                    }
                    DeleteCopyButton(problem: $problem)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
            }
            .fixedSize(horizontal: false, vertical: true)
            .background(Palette.niebla)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("deleted-notice")
        }
    }
}

/// The two confirmations (§7.2, §7.3): what gets deleted, then the master
/// password. Touch ID, where `klavd` has it set up, comes up when the
/// person clicks «Delete my account», before the password is checked.
struct MacDeleteAccountSheet: View {
    @EnvironmentObject private var model: MacModel
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
        VStack(alignment: .leading, spacing: 12) {
            Title("Delete your account?", size: 22)
            switch step {
            case .what: what
            case .password: passwordStep
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Palette.papel)
        .interactiveDismissDisabled(busy)
    }

    private var what: some View {
        VStack(alignment: .leading, spacing: 12) {
            paragraph("Klav deletes everything your account has on the server: your vaults with their items, versions and files, your devices, your agents and the audit log.")
            paragraph("It’s deleted on \(deleteDay). Until then you can cancel it from any of your devices. Your agents stop working now.")
            paragraph("Klav can’t export your vault yet: if you want to keep something, copy it first.")
            paragraph("Not deleted: the copy on your devices until you delete it, your emergency kit, and anything you copied out of Klav.")
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button("Continue") {
                    step = .password
                    focused = true
                }
                .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                .accessibilityIdentifier("delete-account-continue")
            }
            .padding(.top, 8)
        }
    }

    private var passwordStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            paragraph("Enter your master password to delete the account \(model.info?.email ?? "").")
            SecureField("", text: $password, prompt: placeholder("Master password"))
                .textFieldStyle(.plain)
                .focused($focused)
                .inputBox(focused: focused)
                .onSubmit(submit)
                .accessibilityLabel(Text("Master password"))
                .accessibilityIdentifier("delete-account-password")
            if model.confirmingDeletion, model.info?.touchIdEnrolled == true {
                Text("macOS asks on behalf of Klav’s background service, the same one the extension and the CLI use.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let problem { Notice(text: problem) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                    .disabled(busy)
                Button(action: submit) { Text(busy ? "Checking…" : "Delete my account") }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(busy || password.isEmpty)
                    .accessibilityIdentifier("delete-account-confirm")
            }
            .padding(.top, 4)
        }
        .onAppear { focused = true }
    }

    private func paragraph(_ key: LocalizedStringKey) -> some View {
        Text(key)
            .font(.ui(13.5)).foregroundStyle(Palette.tinta)
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
            } catch KlavError.BiometryUnavailable(let message) where message.contains("changed") {
                // klavd forgot the enrolment, as unlocking does: from now
                // on the password alone asks (ADR 0037 §1, D-D).
                problem = String(localized: "Touch ID changed on this Mac, so Klav stopped using it here. Enter the master password again to delete the account.")
                busy = false
            } catch KlavError.BiometryUnavailable {
                // Klav uses Touch ID here: the password alone does not ask
                // (ADR 0037 §1, T162). Say what does.
                problem = String(localized: "Touch ID isn’t available right now, and Klav uses it on this Mac to delete the account. Open the lid (or unlock the Mac with its password if Touch ID is locked) and try again, or delete it from another of your devices.")
                busy = false
            } catch {
                problem = describe(error)
                busy = false
            }
        }
    }
}

/// Settings › Account after the deletion (§7.6): what was deleted, the
/// kit, and «Delete this Mac’s copy». The window shows the vault,
/// read-only, under `DeletedBand` (D-C).
struct DeletedAccountContent: View {
    @EnvironmentObject private var model: MacModel
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Title("Klav deleted your account", size: 22)
            Text("On \(deletionDay(model.deletedAt ?? 0)), everything in \(model.info?.email ?? "") was deleted from the server. This Mac still keeps an encrypted copy.")
                .font(.ui(14)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text("Read-only: you can search and copy, but not edit or sync.")
                .font(.ui(14)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text("Destroy your emergency kit too: with it and your password, any leftover copy opens.")
                .font(.ui(14)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if let problem { Notice(text: problem) }
            DeleteCopyButton(problem: $problem)
                .padding(.top, 4)
        }
    }
}

/// «Delete this Mac’s copy», after a confirmation: Klav can't export yet,
/// and a server that only says the account is gone must not get the
/// person to delete their last copy in one click (D-C). Works with `klavd`
/// locked: it stops `klavd` and deletes the files.
struct DeleteCopyButton: View {
    @Binding var problem: String?
    @State private var confirm = false

    var body: some View {
        Button("Delete this Mac’s copy…") { confirm = true }
            .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
            .fixedSize()
            .accessibilityIdentifier("deleted-delete-copy")
            .sheet(isPresented: $confirm) { DeleteCopySheet(problem: $problem) }
    }
}

/// The confirmation, as a sheet rather than the system's dialog: there
/// the destructive button is the default one, and a stray Return deletes
/// the copy. Here Return does nothing and Escape cancels, as in «Delete
/// my account» and «Uninstall».
///
/// Generated passwords that never went up are only on this Mac (ADR 0037,
/// Q3 of the re-review): the sheet counts them first, lists them to copy,
/// and offers «Delete anyway» instead of the usual button.
struct DeleteCopySheet: View {
    @Binding var problem: String?
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.dismiss) private var dismiss
    @State private var deleting = false
    /// What would be lost; `nil` while Klav checks.
    @State private var loss: UnsentLoss?
    @State private var unsent: [GeneratedEntryInfo] = []
    @State private var listProblem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Title("Delete this Mac’s copy?", size: 22)
            Text("Klav can’t export your vault yet: what you don’t copy elsewhere first is lost.")
                .font(.ui(13.5)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if let loss, loss != .nothing {
                unsentPart(loss)
            }
            if let listProblem { Notice(text: listProblem) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                    .disabled(deleting)
                if let loss, loss != .nothing {
                    Button(deleting ? String(localized: "Deleting…") : String(localized: "Delete anyway")) {
                        deleteCopy(discardUnsent: true)
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(deleting)
                    .accessibilityIdentifier("delete-copy-anyway")
                } else {
                    Button(deleting ? String(localized: "Deleting…") : String(localized: "Delete this Mac’s copy")) {
                        deleteCopy(discardUnsent: false)
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(deleting || loss == nil)
                    .accessibilityIdentifier("delete-copy-confirm")
                }
            }
            .padding(.top, 8)
        }
        .padding(24)
        .frame(width: 440)
        .background(Palette.papel)
        .interactiveDismissDisabled(deleting)
        .task { await check() }
        // The master password for a generated password (ADR 0041).
        .sheet(item: model.passwordPromptHere(.deleteCopy)) { prompt in
            PasswordSheet(prompt: prompt).environmentObject(model)
        }
        .onDisappear { model.withdrawPrompt(over: .deleteCopy) }
    }

    @ViewBuilder
    private func unsentPart(_ loss: UnsentLoss) -> some View {
        switch loss {
        case .counted(let generated, _):
            Text("\(Int(generated)) generated passwords never reached your account: they’re only on this Mac. Copy them somewhere else before you delete this copy.")
                .font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("delete-copy-unsent")
            if !unsent.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(unsent.enumerated()), id: \.element.createdAt) { index, entry in
                        if index > 0 { Rule() }
                        row(entry)
                    }
                }
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            }
        case .unknown:
            Text("Generated passwords that never reached your account may be waiting on this Mac. Unlock Klav to see and copy them; if you delete this copy, any are lost.")
                .font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("delete-copy-unsent")
        case .nothing:
            EmptyView()
        }
    }

    private func row(_ entry: GeneratedEntryInfo) -> some View {
        let when = Date(timeIntervalSince1970: TimeInterval(entry.createdAt) / 1000)
            .formatted(date: .abbreviated, time: .shortened)
        return HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.host ?? String(localized: "No site"))
                    .font(.ui(13.5, .medium)).foregroundStyle(Palette.tinta)
                Text(when).font(.ui(12)).foregroundStyle(Palette.gris)
            }
            Spacer(minLength: 8)
            IconButton(icon: .copy, label: "Copy", size: 26) { copy(entry) }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// Counts what never went up, and lists it while `klavd` is unlocked.
    private func check() async {
        let found = await model.deleteCopyCheck()
        if case .counted = found {
            do {
                unsent = try await model.unsentGenerated()
            } catch {
                listProblem = describe(error)
            }
        }
        loss = found
    }

    private func copy(_ entry: GeneratedEntryInfo) {
        let at = entry.createdAt
        Task {
            do {
                let value = try await model.value(
                    host: .deleteCopy, { try $0.generatedValue(createdAt: at) },
                    withPassword: { try $0.generatedValueWithPassword(createdAt: at, password: $1) })
                model.copy(value)
            } catch is CancellationError {
            } catch {
                listProblem = describe(error)
            }
        }
    }

    private func deleteCopy(discardUnsent: Bool) {
        deleting = true
        problem = nil
        let installer = installer
        Task {
            do {
                try await model.deleteThisCopy(discardUnsent: discardUnsent) {
                    await installer.restartDaemonIfRegistered()
                }
            } catch KlavError.Denied {
                // Something waits by now: the sheet says what, and stays.
                deleting = false
                await check()
                if loss == .nothing { loss = .unknown }
                return
            } catch {
                problem = describe(error)
            }
            deleting = false
            dismiss()
        }
    }
}
