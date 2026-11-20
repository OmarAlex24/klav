import Foundation

/// The logins for the services iOS asked AutoFill about, without repeats,
/// and the service each one matched first. Filling uses that service, not
/// simply the first one with a host: an item saved for the second service
/// would be refused on the first (layer 11 of the 2026-11 round).
struct SiteMatches {
    private(set) var items: [ItemInfo] = []
    /// Logins saved for a subdomain of a service (ADR 0025), offered apart.
    private(set) var parent: [ParentSuggestion] = []
    /// The service each item matched, by item ID.
    private(set) var services: [String: String] = [:]

    init() {}

    /// The suggestions for one service, in the order iOS gave them.
    mutating func add(_ found: [ItemInfo], for service: String) {
        for item in found where services[item.id] == nil {
            services[item.id] = service
            items.append(item)
        }
    }

    /// The «Saved for a subdomain» group for one service. Add them after
    /// every service's own logins: a login that matches one service is
    /// never also offered as another's parent.
    mutating func addParent(_ found: [ParentSuggestion], for service: String) {
        for p in found where services[p.item.id] == nil {
            services[p.item.id] = service
            parent.append(p)
        }
    }

    /// Keeps only some items (the ones with a code, for a code field).
    mutating func keep(where wanted: (ItemInfo) -> Bool) {
        items = items.filter(wanted)
        parent = parent.filter { wanted($0.item) }
        let kept = Set(items.map(\.id) + parent.map(\.item.id))
        services = services.filter { kept.contains($0.key) }
    }
}
