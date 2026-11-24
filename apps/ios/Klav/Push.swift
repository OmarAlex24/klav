import UIKit
import UserNotifications

/// Which request a notification is about (ADR 0018 §5). The payload only
/// carries the kind and the ID; the app asks the server for the rest.
enum PushRoute: Equatable {
    case approval(String)
    case agent(String)
    /// A task request (ADR 0021 §8).
    case task(String)
    /// A secret request from an agent (ADR 0046).
    case secretRequest(String)

    init?(userInfo: [AnyHashable: Any]) {
        guard let klav = userInfo["klav"] as? [String: Any],
              let type = klav["type"] as? String,
              let id = klav["id"] as? String, !id.isEmpty
        else { return nil }
        switch type {
        case "approval": self = .approval(id)
        case "agent": self = .agent(id)
        case "task": self = .task(id)
        case "secret_request": self = .secretRequest(id)
        default: return nil
        }
    }
}

enum Push {
    /// A notice about the account itself (ADR 0037 §5.4: asked, canceled
    /// or deleted), with no ID: the app learns which by syncing.
    static func isAccount(_ userInfo: [AnyHashable: Any]) -> Bool {
        (userInfo["klav"] as? [String: Any])?["type"] as? String == "account"
    }

    /// Development builds get their pushes from the APNs sandbox. Read from
    /// the build (`KLAV_APS_ENVIRONMENT`), not from `#if DEBUG`.
    static var sandbox: Bool {
        (Bundle.main.object(forInfoDictionaryKey: "KlavApsEnvironment") as? String) != "production"
    }

    /// The APNs token as the server wants it: lowercase hex.
    static func hex(_ token: Data) -> String {
        token.map { String(format: "%02x", $0) }.joined()
    }

    /// Asks once whether Klav may notify, and gets a token when it may.
    static func prepare() async {
        let center = UNUserNotificationCenter.current()
        var status = await center.notificationSettings().authorizationStatus
        if status == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
            status = await center.notificationSettings().authorizationStatus
        }
        if status == .authorized || status == .provisional {
            await UIApplication.shared.registerForRemoteNotifications()
        }
    }

    static func status() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }
}

/// Receives the APNs token and the notifications. Set up at launch, before
/// any view exists: a tap that launches the app arrives here first, so the
/// route waits until the model is attached.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, @preconcurrency UNUserNotificationCenterDelegate {
    weak var model: AppModel? {
        didSet { deliver() }
    }

    private var pendingToken: String?
    private var pendingRoute: PushRoute?
    private var pendingAccount = false

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        pendingToken = Push.hex(deviceToken)
        deliver()
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        appLog.error("push: no token: \(error.localizedDescription, privacy: .private)")
    }

    /// In front: show the banner and refresh the requests on screen.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        appLog.info("push: received in front")
        if Push.isAccount(notification.request.content.userInfo) {
            model?.accountChanged()
        } else {
            Task { await model?.loadRequests() }
        }
        completionHandler([.banner, .list, .sound])
    }

    /// Opened: show that request.
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let userInfo = response.notification.request.content.userInfo
        pendingRoute = PushRoute(userInfo: userInfo)
        if Push.isAccount(userInfo) { pendingAccount = true }
        appLog.info("push: opened")
        deliver()
        completionHandler()
    }

    private func deliver() {
        guard let model else { return }
        if let token = pendingToken {
            pendingToken = nil
            model.pushToken(token)
        }
        if let route = pendingRoute {
            pendingRoute = nil
            model.open(route)
        }
        if pendingAccount {
            pendingAccount = false
            model.accountChanged()
        }
    }
}
