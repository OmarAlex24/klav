import SwiftUI

/// The AutoFill sheet: the keyhole while it waits for Face ID, then the
/// logins (or the live codes) for the site; for a page that asks for a
/// passkey, the site's passkeys first (ADR 0020 §11).
struct CredentialView: View {
    @EnvironmentObject private var model: CredentialModel

    var body: some View {
        VStack(spacing: 0) {
            bar
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    switch model.phase {
                    case .locked, .unlocking:
                        locked
                    case .needsApp(let message):
                        needsApp(message)
                    case .list(let listed):
                        problem
                        list(listed)
                    case .replace(let title):
                        replace(title)
                    case .filling:
                        waiting
                            .font(.ui(16))
                            .foregroundStyle(Palette.gris)
                            .frame(maxWidth: .infinity)
                            .padding(.top, 40)
                    }
                }
            }
        }
        .background(Palette.papel.ignoresSafeArea())
        .tint(Palette.tinta)
        .onAppear { model.appear() }
    }

    /// What the sheet is doing while it waits.
    private var waiting: Text {
        if case .register = model.ask { return Text("Saving the passkey…") }
        return model.signing ? Text("Signing in…") : Text("Filling…")
    }

    @ViewBuilder
    private var problem: some View {
        if let problem = model.problem {
            Notice(text: problem).padding(.horizontal, 20).padding(.top, 16)
        }
    }

    private var bar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Wordmark(size: 18)
                if let host = model.host {
                    (model.ask.wantsCode ? Text("Code for \(host)") : Text("For \(host)"))
                        .font(.ui(13, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .lineLimit(1)
                }
            }
            Spacer()
            Button("Cancel") { model.cancel() }
                .buttonStyle(SecondaryButtonStyle(compact: true))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .overlay(alignment: .bottom) { Rule() }
    }

    /// The same keyhole as the app's lock screen, smaller.
    private var locked: some View {
        VStack(alignment: .leading, spacing: 0) {
            DitherView(kind: .keyhole(open: 0), pixel: 4)
                .background(Palette.marino)
                .frame(height: 200)
                .clipped()
            VStack(alignment: .leading, spacing: 0) {
                lockedTitle
                Text("Klav uses Face ID here; the master password is only typed in the app.")
                    .font(.ui(14, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 6)
                if case .register = model.ask {
                    // Before Face ID: after it, the sheet closes at once
                    // (ADR 0020 §11, T87).
                    Notice(text: String(localized: "Klav keeps it on this iPhone. Open Klav to sync this passkey to your other devices."),
                           tone: .info)
                        .padding(.top, 16)
                }
                if let problem = model.problem {
                    Notice(text: problem).padding(.top, 16)
                }
                Button {
                    model.unlock()
                } label: {
                    Text(model.phase == .unlocking ? "Waiting for Face ID…" : "Unlock with Face ID")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(model.phase == .unlocking)
                .padding(.top, 22)
            }
            .padding(20)
        }
    }

    private var lockedTitle: Title {
        switch model.ask {
        case .register: return Title("Save a passkey", size: 22)
        case .passkey, .passkeys: return Title("Unlock to sign in", size: 22)
        default: return Title("Unlock to fill", size: 22)
        }
    }

    /// The account already has a passkey in that login: replace it, or
    /// keep it and leave (the page gets an error).
    private func replace(_ title: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Title("Replace the passkey?", size: 22)
            Text("\(title) already has a passkey for this account. The new one replaces it, and the old one stops working.")
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
            Button("Replace") { model.answerReplace(true) }
                .buttonStyle(PrimaryButtonStyle())
                .padding(.top, 22)
            Button("Keep it") { model.answerReplace(false) }
                .buttonStyle(SecondaryButtonStyle())
                .padding(.top, 10)
        }
        .padding(20)
    }

    /// Only the app can unlock now: the keyhole in greys, closed.
    private func needsApp(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            DitherView(kind: .keyhole(open: 0), palette: .mask, pixel: 4)
                .frame(height: 140)
                .clipped()
            VStack(alignment: .leading, spacing: 0) {
                Title("Open Klav first", size: 22)
                Notice(text: message, tone: .info).padding(.top, 14)
                Text("Only Face ID is used here: the master password is typed in the app.")
                    .font(.ui(14, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 12)
            }
            .padding(20)
        }
    }

    @ViewBuilder
    private func list(_ listed: Listed) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            if listed.passkeys.isEmpty && listed.logins.isEmpty && !listed.parent.isEmpty {
                let site = model.host ?? String(localized: "this site")
                Text("No login is saved for \(site) itself.")
                    .font(.ui(14, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 16)
            }
            if listed.isEmpty {
                let site = model.host ?? String(localized: "this site")
                (model.ask.wantsCode
                     ? Text("No item with a code is for \(site).")
                     : model.ask.isPasskey ? Text("No passkey or login is for \(site).") : Text("No login is for \(site)."))
                    .font(.ui(16, .medium))
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Klav only fills on the sites saved in each item. Add this site from the app.")
                    .font(.ui(14, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 6)
            }
            if !listed.passkeys.isEmpty {
                SectionLabel("Passkeys")
                    .padding(.bottom, 4)
                ForEach(listed.passkeys, id: \.credentialId) { passkey in
                    row(passkey)
                }
            }
            if !listed.logins.isEmpty {
                SectionLabel(model.ask.wantsCode ? "Choose the code"
                             : listed.passkeys.isEmpty ? "Choose how to sign in" : "Passwords")
                    .padding(.top, listed.passkeys.isEmpty ? 0 : 20)
                    .padding(.bottom, 4)
                ForEach(listed.logins, id: \.id) { item in
                    row(item)
                }
            }
            // ADR 0025: logins saved for a subdomain of this site, apart and
            // after, with the host they were saved for. Only on a tap.
            if !listed.parent.isEmpty {
                SectionLabel("Saved for a subdomain")
                    .padding(.top, listed.logins.isEmpty && listed.passkeys.isEmpty ? 0 : 20)
                    .padding(.bottom, 4)
                ForEach(listed.parent, id: \.item.id) { p in
                    row(p.item, savedFor: p.savedHost)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 20)
        .padding(.bottom, 24)
    }

    /// A login: its icon, title and user, and «Fill»; for a code,
    /// the live code instead. The whole row fills. `savedFor`: a login of
    /// the «Saved for a subdomain» group, with that host under the user.
    private func row(_ item: ItemInfo, savedFor: String? = nil) -> some View {
        Button {
            model.choose(item, savedFor: savedFor)
        } label: {
            HStack(spacing: 12) {
                Tile(title: item.title, site: item.confirmedUrls.first)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(.ui(16, .medium))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(1)
                    if let savedFor {
                        Text(subtitle(item, savedFor: savedFor))
                            .font(.ui(14, relativeTo: .subheadline))
                            .foregroundStyle(Palette.gris)
                            .lineLimit(1)
                    } else if let sub = item.listSubtitle {
                        Text(sub)
                            .font(.ui(14, relativeTo: .subheadline))
                            .foregroundStyle(Palette.gris)
                            .lineLimit(1)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if model.ask.wantsCode {
                    LiveCode(id: item.id, title: item.title, style: .row, fetch: model.fetchCode)
                } else {
                    // Looks like a button; the row is the button.
                    Text("Fill")
                        .font(.ui(14, .medium))
                        .foregroundStyle(Palette.tinta)
                        .padding(.horizontal, 12)
                        .frame(minHeight: 36)
                        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                }
            }
            .frame(minHeight: 64)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowStyle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.ask.wantsCode
                            ? Text("Fill the code for \(item.title)")
                            : Text("Fill with \(item.title), \(savedFor.map { subtitle(item, savedFor: $0) } ?? item.subtitle)"))
        .accessibilityAddTraits(.isButton)
    }

    /// A passkey of the site: «Passkey · account», and «Sign in».
    private func row(_ passkey: PasskeyIdentityInfo) -> some View {
        let account = passkey.userName.isEmpty ? passkey.title : passkey.userName
        return Button {
            model.choose(passkey)
        } label: {
            HStack(spacing: 12) {
                Tile(title: passkey.title, site: "https://\(passkey.rpId)")
                VStack(alignment: .leading, spacing: 2) {
                    Text(passkey.title)
                        .font(.ui(16, .medium))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(1)
                    Text("Passkey · \(account)")
                        .font(.ui(14, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text("Sign in")
                    .font(.ui(14, .medium))
                    .foregroundStyle(Palette.tinta)
                    .padding(.horizontal, 12)
                    .frame(minHeight: 36)
                    .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            }
            .frame(minHeight: 64)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowStyle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Sign in with the passkey for \(account), \(passkey.title)"))
        .accessibilityAddTraits(.isButton)
    }

    /// «ana · Saved for my.1password.com».
    private func subtitle(_ item: ItemInfo, savedFor: String) -> String {
        let saved = String(localized: "Saved for \(savedFor)")
        guard let user = item.username, !user.isEmpty else { return saved }
        return "\(user) · \(saved)"
    }
}

/// Mist and a cobalt line on the left while pressed, like the app's rows.
private struct RowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 8)
            .background(configuration.isPressed ? Palette.niebla : Color.clear)
            .overlay(alignment: .leading) {
                Rectangle().fill(configuration.isPressed ? Palette.cobalto : Color.clear).frame(width: 2)
            }
            .padding(.horizontal, -8)
    }
}
