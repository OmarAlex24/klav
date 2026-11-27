import Foundation

/// The menu bar's quick search: what it matches, in what order, and what
/// each result's buttons copy. Pure, so the tests can check it without a
/// panel.
enum QuickSearch {
    /// How many results the panel shows.
    static let limit = 6

    /// Every live item, values aside: the panel searches it as the person
    /// types, without asking `klavd` again.
    static let everything = ItemQuery(vaultId: nil, projectId: nil, text: nil, kind: nil, trash: false)
    /// The live items with a one-time code (the «Codes» view's filter).
    static let withCodes = ItemQuery(vaultId: nil, projectId: nil, text: nil, kind: nil, codes: true, trash: false)

    /// The items matching `query`, as `klavd`'s list matches it (title,
    /// user name, sites and tags, ignoring case), titles that start with
    /// it first, then titles that hold it, then the rest, each group in
    /// the vault's order. An empty query keeps every item, in that order.
    static func filter(_ items: [ItemInfo], query: String) -> [ItemInfo] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return items }
        var starts: [ItemInfo] = [], inTitle: [ItemInfo] = [], elsewhere: [ItemInfo] = []
        for item in items {
            let title = item.title.lowercased()
            if title.hasPrefix(q) {
                starts.append(item)
            } else if title.contains(q) {
                inTitle.append(item)
            } else if item.username?.lowercased().contains(q) == true
                        || item.urls.contains(where: { $0.lowercased().contains(q) })
                        || item.tags.contains(where: { $0.lowercased().contains(q) }) {
                elsewhere.append(item)
            }
        }
        return starts + inTitle + elsewhere
    }

    /// What a result's button copies.
    enum Action: Equatable {
        case username, password, code, key
    }

    /// A result's buttons: «User» when it has a user name, «Password» for
    /// a login, «Code» when it has a one-time code and «Key» for an API key.
    static func actions(_ item: ItemInfo, hasCode: Bool) -> [Action] {
        var actions: [Action] = []
        if item.username != nil { actions.append(.username) }
        if item.kind == .login { actions.append(.password) }
        if item.kind == .totp || hasCode { actions.append(.code) }
        if item.kind == .apiKey { actions.append(.key) }
        return actions
    }

    /// What Return copies on the selected result: the password of a login,
    /// the code of a one-time code, the key of an API key, otherwise the
    /// user name. `nil`: nothing to copy, so Return opens the item.
    static func primary(_ item: ItemInfo, hasCode: Bool) -> Action? {
        switch item.kind {
        case .login: return .password
        case .totp: return .code
        case .apiKey: return .key
        default:
            let buttons = actions(item, hasCode: hasCode)
            return buttons.contains(.code) ? .code : buttons.first
        }
    }

    /// The field «Key» copies from an API key: its main secret, `api_key`
    /// (what the credential proxy injects), else its first filled secret
    /// that is not a one-time code or a file (an imported key may name it
    /// otherwise).
    static func keyField(of detail: ItemDetail) -> String? {
        let filled = detail.fields.filter { $0.filled && $0.kind != .file }
        if let main = filled.first(where: { $0.name == "api_key" }) { return main.name }
        return filled.first(where: { $0.secret && $0.kind != .totp })?.name
    }
}

extension MacModel {
    /// Reads the quick search's list once per `generation` while unlocked,
    /// at low priority: the panel searches it in memory. A read keeps the
    /// last list until it lands, and a failed one keeps it too (the next
    /// refresh tries again). Then which items have a one-time code: `klavd`
    /// opens each item's details the first time it is asked, so that goes
    /// after the list, never before it.
    func loadQuickItems() {
        guard phase == .unlocked, quickReadGeneration != generation else { return }
        let generation = self.generation
        quickReadGeneration = generation
        quickReadsStarted += 1
        let number = quickReadsStarted, epoch = quickEpoch
        Task {
            do {
                let all = try await run(priority: .utility) { try $0.items(query: QuickSearch.everything) }
                // Locked, signed out or overtaken meanwhile: nothing lands.
                guard epoch == quickEpoch, phase == .unlocked, number > quickReadsLanded else { return }
                quickReadsLanded = number
                quickItems = all
                quickProblem = nil
            } catch {
                guard epoch == quickEpoch else { return }
                if quickReadGeneration == generation { quickReadGeneration = nil }
                if let error = error as? KlavError, case .Locked = error {
                    refresh()
                } else if quickItems == nil {
                    quickProblem = describe(error)
                }
                return
            }
            let codes = try? await run(priority: .utility) { try $0.items(query: QuickSearch.withCodes) }
            guard let codes, epoch == quickEpoch, number == quickReadsLanded else { return }
            quickCodes = Set(codes.map(\.id))
        }
    }

    /// Locked, signed out or another account: the list goes, and a read
    /// that started before never lands.
    func forgetQuickItems() {
        quickEpoch += 1
        quickReadGeneration = nil
        quickItems = nil
        quickCodes = []
        quickProblem = nil
    }

    /// The window opens on `id`, in All items, whatever it showed before
    /// (the menu bar's results). The vault list drops its own search and
    /// repository filter so the item is in it.
    func openItem(_ id: String) {
        if section != .vault(.all) { section = .vault(.all) }
        selectedItem = id
        itemOpenRequests += 1
    }

    /// The value a result's button copies, through the presence gate like
    /// the window's (ADR 0041): `onAsk` runs when the master password's
    /// sheet is set up, to show the window it opens over.
    func quickValue(_ action: QuickSearch.Action, of item: ItemInfo,
                    onAsk: (@MainActor () -> Void)? = nil) async throws -> String {
        let id = item.id
        switch action {
        case .code:
            return try await value(onAsk: onAsk, { try $0.totp(id: id) },
                                   withPassword: { try $0.totpWithPassword(id: id, password: $1) }).code
        case .username, .password, .key:
            let field: String
            switch action {
            case .username: field = "username"
            case .password: field = "password"
            default:
                let detail = try await run { try $0.item(id: id) }
                guard let name = QuickSearch.keyField(of: detail) else { throw QuickSearchError.noKey }
                field = name
            }
            return try await value(onAsk: onAsk, { try $0.fieldValue(id: id, field: field) },
                                   withPassword: { try $0.fieldValueWithPassword(id: id, field: field, password: $1) })
        }
    }
}

enum QuickSearchError: LocalizedError {
    /// An API key with no secret to copy.
    case noKey

    var errorDescription: String? {
        String(localized: "This API key has no value to copy yet.")
    }
}
