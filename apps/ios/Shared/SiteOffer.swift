import Foundation

/// «Add <host> to this item» (ADR 0025 §2). The AutoFill extension filled a
/// login saved for a subdomain on its parent's page; it does not sync or
/// write the vault, so it leaves the offer here and the app asks the next
/// time it opens. Only the item's ID and title and two hosts, never a
/// secret: the same kind of data QuickType already keeps.
struct SiteOffer: Codable, Equatable, Identifiable {
    /// The item.
    let itemId: String
    let title: String
    /// The page it was filled on, to add (`1password.com`).
    let host: String
    /// The host it was saved for (`my.1password.com`).
    let savedFor: String
    let at: Date

    var id: String { "\(itemId)|\(host)" }

    private static let key = "siteOffer"
    /// An offer older than this is dropped unasked.
    static let lifetime: TimeInterval = 7 * 24 * 3600

    /// Keeps one offer: the last login filled this way.
    static func leave(_ offer: SiteOffer, in defaults: UserDefaults = KlavHome.defaults) {
        if let data = try? JSONEncoder().encode(offer) {
            defaults.set(data, forKey: key)
        }
    }

    /// The offer waiting, if it is recent enough.
    static func pending(in defaults: UserDefaults = KlavHome.defaults, now: Date = Date()) -> SiteOffer? {
        guard let data = defaults.data(forKey: key),
              let offer = try? JSONDecoder().decode(SiteOffer.self, from: data) else { return nil }
        guard now.timeIntervalSince(offer.at) < lifetime else {
            clear(in: defaults)
            return nil
        }
        return offer
    }

    static func clear(in defaults: UserDefaults = KlavHome.defaults) {
        defaults.removeObject(forKey: key)
    }
}
