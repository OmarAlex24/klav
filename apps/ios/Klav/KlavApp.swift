import SwiftUI
import UIKit

@main
struct KlavApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(model.preferences)
                .onAppear {
                    model.start()
                    delegate.model = model
                }
                .onChange(of: scenePhase) { _, phase in model.scene(phase) }
                // `otpauth://` from «Set Up Codes In», the camera or Safari,
                // and Google Authenticator's exports (ADR 0035).
                .onOpenURL { model.openLink($0) }
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Palette.papel.ignoresSafeArea()
            switch model.phase {
            case .starting:
                Color.clear
            case .broken(let message):
                BrokenView(message: message)
            case .signedOut:
                SignInView()
            case .locked:
                LockView()
            case .unlocked:
                HomeView()
                    .accessibilityHidden(model.autofillWelcome != .hidden)
            }
            // After signing in, while Klav is off as an AutoFill provider.
            if model.phase == .unlocked, model.deletedAt == nil, model.autofillWelcome != .hidden {
                AutofillWelcomeView()
                    .transition(.opacity)
            }
            if let toast = model.toast, !model.covered {
                VStack {
                    Spacer()
                    ToastView(toast: toast)
                }
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .id(toast.id)
            }
            if model.covered {
                // Instant: the app switcher takes its picture right away.
                // `PrivacyShield` covers the sheets and dialogs too; this
                // one is in case there is no window scene.
                PrivacyCover()
            }
        }
        .tint(Palette.tinta)
        .animation(.easeOut(duration: 0.2), value: model.toast?.id)
        .animation(.easeOut(duration: 0.2), value: model.autofillWelcome == .hidden)
    }
}

extension View {
    /// The app's toast («Copied…») inside a sheet, which covers the root's.
    func toastHost(_ model: AppModel, when shown: Bool = true) -> some View {
        overlay {
            if shown, let toast = model.toast, !model.covered {
                VStack {
                    Spacer()
                    ToastView(toast: toast)
                }
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .id(toast.id)
            }
        }
        .animation(.easeOut(duration: 0.2), value: model.toast?.id)
    }
}

/// The privacy cover in a window of its own, above the app's sheets,
/// dialogs and alerts (a sheet is presented above the root view, so a
/// cover inside it does not hide the sheet). Shown and hidden without
/// animation, as soon as the scene changes.
@MainActor
final class PrivacyShield {
    static let shared = PrivacyShield()

    private(set) var window: UIWindow?

    /// The cover is up.
    var isShowing: Bool { window.map { !$0.isHidden } ?? false }

    func show() {
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first(where: { $0.activationState != .unattached }) else { return }
        if window?.windowScene !== scene {
            let cover = UIWindow(windowScene: scene)
            cover.windowLevel = .alert + 1
            let host = UIHostingController(rootView: PrivacyCover())
            host.view.backgroundColor = .clear
            cover.rootViewController = host
            cover.accessibilityElementsHidden = true
            window = cover
        }
        UIView.performWithoutAnimation {
            window?.isHidden = false
            window?.layoutIfNeeded()
        }
    }

    func hide() {
        UIView.performWithoutAnimation { window?.isHidden = true }
    }
}

/// What the app switcher shows: the keyhole's noise, never the vault.
struct PrivacyCover: View {
    var body: some View {
        DitherView(kind: .keyhole(open: 0), pixel: 4)
            .background(Palette.marino)
            .ignoresSafeArea()
            .accessibilityHidden(true)
    }
}

/// The local storage could not be opened (should not happen).
struct BrokenView: View {
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Wordmark()
            Title("Klav couldn’t open its data")
                .padding(.top, 18)
            Notice(text: message)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
