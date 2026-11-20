import AuthenticationServices
import SwiftUI

/// Whether the welcome to AutoFill is on screen: asking the person to turn
/// Klav on in iOS Settings, or confirming it is on before it closes.
enum AutofillWelcome: Equatable {
    case hidden
    case asking
    case done

    /// After signing in, while Klav is off as an AutoFill provider and the
    /// person has not said «Not now». Unknown (`nil`) never asks.
    static func offered(enabled: Bool?, dismissed: Bool) -> Bool {
        enabled == false && !dismissed
    }
}

/// Over the vault, after signing in: how to turn Klav on in Settings ›
/// General › AutoFill & Passwords, and a button that opens that page. The
/// keyhole stays in greys (closed, as in the AutoFill sheet's «Open Klav
/// first») until iOS reports Klav on; then the box fills and the keyhole
/// floods with light, as when the vault opens.
struct AutofillWelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var typeSize

    /// 0…1 while the keyhole floods.
    @State private var flood: Double = 0
    @State private var problem: String?

    private var done: Bool { model.autofillWelcome == .done }

    var body: some View {
        GeometryReader { geo in
            VStack(spacing: 0) {
                field
                    .frame(height: typeSize.isAccessibilitySize ? 96 : geo.size.height * 0.28)
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Group {
                            if done {
                                Title("Klav fills in now")
                            } else {
                                Title("Fill passwords with Klav")
                            }
                        }
                        Text(done
                             ? "Tap a password field in Safari or another app and pick a login above the keyboard."
                             : "Safari and other apps only offer your Klav logins once Klav is turned on in the iPhone’s Settings.")
                            .font(.ui(15, relativeTo: .subheadline))
                            .foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 8)
                        SettingsPath(on: done)
                            .padding(.top, 28)
                        if let problem {
                            Notice(text: problem).padding(.top, 16)
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.top, 26)
                    .padding(.bottom, 16)
                    .frame(maxWidth: 520)
                    .frame(maxWidth: .infinity)
                }
                actions
                    .padding(.horizontal, 24)
                    .padding(.bottom, 16)
                    .frame(maxWidth: 520)
                    .frame(maxWidth: .infinity)
            }
        }
        .background(Palette.papel)
        // VoiceOver stays here, not on the vault underneath.
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isModal)
        .accessibilityIdentifier("autofill-welcome")
        .onChange(of: done) { _, done in
            if done { confirm() }
        }
    }

    private var field: some View {
        DitherView(kind: .keyhole(open: flood), palette: done ? .blue : .mask, pixel: 4, keep: flood == 0 || flood == Self.lit)
            .background(done ? Palette.marino : Palette.papel)
            .clipped()
            .overlay(alignment: .bottom) { Rule() }
    }

    @ViewBuilder
    private var actions: some View {
        VStack(spacing: 6) {
            if !done {
                Button("Open AutoFill & Passwords", action: openSettings)
                    .buttonStyle(PrimaryButtonStyle())
                    .accessibilityIdentifier("autofill-open-settings")
                Button("Not now") { model.dismissAutofillWelcome() }
                    .buttonStyle(LinkButtonStyle())
                    .accessibilityIdentifier("autofill-not-now")
                Text("You’ll find this again in Klav’s Settings › AutoFill.")
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.top, 10)
    }

    private func openSettings() {
        problem = nil
        Task {
            do {
                try await ASSettingsHelper.openCredentialProviderAppSettings()
            } catch {
                appLog.error("autofill: settings did not open: \(error.localizedDescription, privacy: .private)")
                problem = String(localized: "Settings didn’t open. Open the iPhone’s Settings › General › AutoFill & Passwords and turn on Klav.")
            }
        }
    }

    /// How far the light spreads: the keyhole glows in blue around it.
    /// A full flood (1, the unlock) would leave the field blank paper.
    static let lit = 0.3

    /// The keyhole lights up in steps (as on unlock); with Reduce Motion
    /// it is lit at once.
    private func confirm() {
        UIAccessibility.post(notification: .announcement,
                             argument: String(localized: "Klav is on. Safari and other apps can fill with it now."))
        guard !reduceMotion else {
            flood = Self.lit
            return
        }
        Task {
            let steps = 8
            for step in 1...steps {
                flood = Self.lit * Double(step) / Double(steps)
                try? await Task.sleep(for: .milliseconds(320 / steps))
            }
        }
    }
}

/// The way through the iPhone's Settings, named as iOS names it: a route
/// down the left joins the pages in the order they are tapped, and the
/// last row is Klav's own switch, drawn as Klav's square box. It fills
/// when iOS reports Klav on.
struct SettingsPath: View {
    let on: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel("In the iPhone’s Settings")
            VStack(spacing: 0) {
                step(Text("Settings"), first: true)
                step(Text("General"))
                step(Text("AutoFill & Passwords"))
                klav
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
            .padding(.top, 6)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("In the iPhone’s Settings, open General, then AutoFill & Passwords, and turn on Klav."))
        .accessibilityValue(on ? Text("On") : Text("Off"))
    }

    private func step(_ name: Text, first: Bool = false) -> some View {
        HStack(spacing: 14) {
            Color.clear.frame(width: 12, height: 1)
            name
                .font(.ui(16))
                .foregroundStyle(Palette.tinta)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.vertical, 12)
            Text(verbatim: "›")
                .font(.ui(18))
                .foregroundStyle(Palette.cruz)
        }
        .background(alignment: .leading) { node(filled: false, top: !first, bottom: true) }
        .overlay(alignment: .bottom) { Rule().padding(.leading, 26) }
    }

    private var klav: some View {
        HStack(spacing: 14) {
            Color.clear.frame(width: 12, height: 1)
            HStack(spacing: 10) {
                KeyGlyphShape()
                    .fill(Palette.tinta)
                    .frame(width: 18, height: 18 * 5 / 8)
                Text(verbatim: "Klav")
                    .font(.ui(16, .medium))
                    .foregroundStyle(Palette.tinta)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 14)
            // The same box as Klav's own switches (SquareToggleStyle).
            ZStack {
                Rectangle().fill(on ? Palette.boton : Palette.papel)
                Rectangle().strokeBorder(Palette.tinta, lineWidth: 1)
                if on {
                    IconView(icon: .check, size: 16).foregroundStyle(Palette.botonTexto)
                }
            }
            .frame(width: 22, height: 22)
            .animation(nil, value: on)
        }
        .background(alignment: .leading) { node(filled: on, top: true, bottom: false) }
    }

    /// A solid stop on the route (not a box: only Klav's row has one), with
    /// the line above and below it; it takes the row's height (it is the
    /// row's background). Klav's stop turns ink once it is on.
    private func node(filled: Bool, top: Bool, bottom: Bool) -> some View {
        VStack(spacing: 0) {
            Rectangle().fill(top ? Palette.cruz : Color.clear).frame(width: 1)
            Rectangle()
                .fill(filled ? Palette.tinta : Palette.cruz)
                .frame(width: 5, height: 5)
            Rectangle().fill(bottom ? Palette.cruz : Color.clear).frame(width: 1)
        }
        .frame(width: 12)
    }
}
