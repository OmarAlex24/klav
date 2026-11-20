import AppKit
import SwiftUI
import UserNotifications

/// Klav for macOS (ADR 0027): always in the menu bar, with a window for
/// the vault and the agents. The Dock icon shows only while the window is
/// open (`LSUIElement`, then `.regular` while it is).
@main
struct KlavMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = Engines.model()
    @StateObject private var installer = Engines.installer()
    @StateObject private var updates = Updates()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environmentObject(model)
                .environmentObject(installer)
        } label: {
            MenuBarLabel()
                .environmentObject(model)
                .environmentObject(installer)
        }
        .menuBarExtraStyle(.window)

        Window("Klav", id: WindowID.main) {
            MainWindow()
                .environmentObject(model)
                .environmentObject(installer)
                .onAppear { delegate.model = model }
        }
        .defaultSize(width: 1040, height: 680)
        .windowResizability(.contentMinSize)
        .defaultLaunchBehavior(.suppressed)
        // Opened at login, no window opens: not at launch, and macOS
        // doesn't bring this one or Settings back from the last session.
        .restorationBehavior(.disabled)
        .commands { KlavCommands(model: model, updates: updates) }

        // Settings › This Mac: the setup again, and uninstalling.
        Settings {
            MacSettingsView()
                .environmentObject(model)
                .environmentObject(installer)
        }
        .restorationBehavior(.disabled)

        #if DEBUG
        // The menu bar's panel in a window, for screenshots (Snapshot.swift).
        Window("Klav menu", id: WindowID.menuPreview) {
            MenuBarView()
                .environmentObject(model)
                .environmentObject(installer)
                .background(Palette.papel)
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)
        #endif
    }
}

enum WindowID {
    static let main = "main"
    static let menuPreview = "menu-preview"
}

/// Which engine: `klavd` of this Mac's `KLAV_HOME`, or the sample vault
/// for screenshots (`-KlavSample YES`, debug builds only).
enum Engines {
    @MainActor
    static func model() -> MacModel {
        #if DEBUG
        if sample {
            let engine = SampleEngine()
            return MacModel(engine: engine, accounts: SampleAccounts(engine: engine))
        }
        #endif
        do {
            let home = try KlavHome.directory().path
            return MacModel(engine: try DaemonEngine(homeDir: home), accounts: LiveAccounts(homeDir: home))
        } catch {
            fatalError("Klav cannot find its home: \(error.localizedDescription)")
        }
    }

    @MainActor
    static func installer() -> Installer {
        #if DEBUG
        if sample {
            let agent: AgentState = UserDefaults.standard.bool(forKey: "KlavSampleAgent") ? .enabled : .notRegistered
            return Installer(paths: .live(), system: SampleSystem(agent: agent), placement: .applications)
        }
        #endif
        return .live()
    }

    static var sample: Bool { UserDefaults.standard.bool(forKey: "KlavSample") }
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    weak var model: MacModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        UNUserNotificationCenter.current().delegate = self
        #if DEBUG
        Snapshot.configure()
        #endif
    }

    /// Closing the window leaves Klav in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async
        -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    /// A request's notification opens the window on the requests.
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run {
            if model?.accountDeleted != true { model?.section = .requests }
            NotificationCenter.default.post(name: .klavOpenMain, object: nil)
        }
    }
}

extension Notification.Name {
    static let klavOpenMain = Notification.Name("dev.klav.mac.open-main")
}

/// Shows the Dock icon while the window is open, and gives focus to it.
struct DockWhileOpen: ViewModifier {
    func body(content: Content) -> some View {
        content
            .onAppear {
                NSApp.setActivationPolicy(.regular)
                #if DEBUG
                // Screenshots (`-KlavOpen`) never take the focus: the person
                // may be typing in another app.
                if UserDefaults.standard.string(forKey: "KlavOpen") != nil { return }
                #endif
                NSApp.activate()
            }
            .onDisappear {
                NSApp.setActivationPolicy(.accessory)
            }
    }
}

/// The app's menus: lock, search and the window's sections.
struct KlavCommands: Commands {
    @ObservedObject var model: MacModel
    @ObservedObject var updates: Updates
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            if updates.enabled {
                Button("Check for Updates…") { updates.check() }
                    .disabled(!updates.canCheck)
            }
            Button("Lock Klav") { model.lock() }
                .keyboardShortcut("l", modifiers: [.command])
                .disabled(model.phase != .unlocked)
            Divider()
            Button("Uninstall Klav from this Mac…") {
                openWindow(id: WindowID.main)
                model.uninstalling = true
            }
        }
        // Items (read-only after the deletion, ADR 0037 D-C), never over
        // an open sheet (the model checks it too).
        CommandGroup(replacing: .newItem) {
            Button("New Item") {
                openWindow(id: WindowID.main)
                model.newItem()
            }
            .keyboardShortcut("n", modifiers: [.command])
            .disabled(!model.canChangeItems || model.sheetOpen)
            Button("Edit Item") {
                openWindow(id: WindowID.main)
                model.editSelected()
            }
            .keyboardShortcut("e", modifiers: [.command])
            .disabled(!model.canChangeItems || model.sheetOpen || model.selectedItem == nil || !model.section.isVault)
        }
        CommandMenu("Go") {
            Button("All items") { model.section = .vault(.all) }
                .keyboardShortcut("1", modifiers: [.command])
            // After the deletion only the vault is left (D-C).
            Group {
                Button("Requests") { model.section = .requests }
                    .keyboardShortcut("2", modifiers: [.command])
                Button("Agents") { model.section = .agents }
                    .keyboardShortcut("3", modifiers: [.command])
                Button("Vault health") { model.section = .health }
                    .keyboardShortcut("4", modifiers: [.command])
                Button("Activity") { model.section = .activity }
                    .keyboardShortcut("5", modifiers: [.command])
                Button("Clients") { model.section = .clients }
                    .keyboardShortcut("6", modifiers: [.command])
                Button("Sandboxes") { model.section = .sandboxes }
                    .keyboardShortcut("7", modifiers: [.command])
            }
            .disabled(model.accountDeleted)
        }
    }
}
