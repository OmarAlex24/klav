import SwiftUI

/// The vault's type tabs, as the extension's `ui/filters.ts`: «All», one
/// per item type and «Codes», the items with a one-time code of any type.
/// A standalone code item has no tab of its own: it is what «Codes» is for.
enum VaultFilter: Hashable, CaseIterable {
    case all, login, codes, card, note, sshKey, apiKey, identity, file

    /// The item type a type tab keeps; nil for «All» and «Codes».
    var kind: Kind? {
        switch self {
        case .login: return .login
        case .card: return .card
        case .note: return .note
        case .sshKey: return .sshKey
        case .apiKey: return .apiKey
        case .identity: return .identity
        case .file: return .file
        case .all, .codes: return nil
        }
    }

    var label: String {
        switch self {
        case .all: return String(localized: "filter.all", defaultValue: "All", comment: "Type tab in the vault")
        case .login: return String(localized: "filter.login", defaultValue: "Logins", comment: "Type tab in the vault")
        case .codes: return String(localized: "filter.codes", defaultValue: "Codes", comment: "Type tab in the vault: items with a one-time code")
        case .card: return String(localized: "filter.card", defaultValue: "Cards", comment: "Type tab in the vault")
        case .note: return String(localized: "filter.note", defaultValue: "Notes", comment: "Type tab in the vault")
        case .sshKey: return String(localized: "filter.sshKey", defaultValue: "SSH keys", comment: "Type tab in the vault")
        case .apiKey: return String(localized: "filter.apiKey", defaultValue: "API keys", comment: "Type tab in the vault")
        case .identity: return String(localized: "filter.identity", defaultValue: "Addresses", comment: "Type tab in the vault")
        case .file: return String(localized: "filter.file", defaultValue: "Files", comment: "Type tab in the vault")
        }
    }

    /// The tab's line icon: the kind's, four squares for «All» and the
    /// stopwatch of one-time codes for «Codes» (`Kind.icon`).
    var icon: Icon {
        switch self {
        case .all: return .grid
        case .codes: return .timer
        default: return kind?.icon ?? .grid
        }
    }

    struct Tab: Equatable {
        let filter: VaultFilter
        /// Nil while klav-core has not said how many items have a code.
        let count: Int?
    }

    /// The tabs to draw: «All» and every filter with something in it, plus
    /// the chosen one even if a search left it empty. One type and no codes
    /// need no tabs at all.
    static func tabs(_ items: [ItemInfo], codes: Int?, chosen: VaultFilter) -> [Tab] {
        var counts: [Kind: Int] = [:]
        for item in items where item.kind != .totp {
            counts[item.kind, default: 0] += 1
        }
        var out: [Tab] = []
        for filter in allCases {
            switch filter {
            case .all:
                out.append(Tab(filter: .all, count: items.count))
            case .codes:
                if (codes ?? 0) > 0 || chosen == .codes { out.append(Tab(filter: .codes, count: codes)) }
            default:
                let count = filter.kind.flatMap { counts[$0] } ?? 0
                if count > 0 || chosen == filter { out.append(Tab(filter: filter, count: count)) }
            }
        }
        return out.count <= 2 && chosen == .all ? [] : out
    }

    /// The items this tab shows. «Codes» needs `codeIds` (nil: not known yet).
    func filtered(_ items: [ItemInfo], codeIds: Set<String>?) -> [ItemInfo] {
        switch self {
        case .all: return items
        case .codes: return codeIds.map { ids in items.filter { ids.contains($0.id) } } ?? []
        default: return items.filter { $0.kind == kind }
        }
    }
}

/// The type tabs under the search: one quiet line, each type's icon, the
/// chosen tab in ink with the 2-point rule that says «chosen» everywhere
/// else, as the generator's types. Scrolls sideways when the types do not
/// fit.
struct VaultTabs: View {
    let tabs: [VaultFilter.Tab]
    @Binding var chosen: VaultFilter
    /// More tabs past each edge: they fade out there instead of being cut.
    @State private var more = Edges()
    /// The icon grows with the tab's text.
    @ScaledMetric(relativeTo: .subheadline) private var iconSize: CGFloat = 16

    struct Edges: Equatable {
        var leading = false
        var trailing = false
    }

    var body: some View {
        ScrollViewReader { scroller in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(tabs, id: \.filter) { tab in
                        button(tab).id(tab.filter)
                    }
                }
            }
            .onScrollGeometryChange(for: Edges.self) { g in
                Edges(leading: g.contentOffset.x > 1,
                      trailing: g.contentSize.width - g.contentOffset.x - g.containerSize.width > 1)
            } action: { _, now in
                more = now
            }
            .mask {
                HStack(spacing: 0) {
                    LinearGradient(colors: [more.leading ? .clear : .black, .black], startPoint: .leading, endPoint: .trailing)
                        .frame(width: 32)
                    Rectangle()
                    LinearGradient(colors: [.black, more.trailing ? .clear : .black], startPoint: .leading, endPoint: .trailing)
                        .frame(width: 32)
                }
            }
            .overlay(alignment: .bottom) { Rule() }
            .onChange(of: chosen) { _, now in
                withAnimation(.snappy) { scroller.scrollTo(now, anchor: .center) }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text("Filter by type"))
    }

    private func button(_ tab: VaultFilter.Tab) -> some View {
        let on = tab.filter == chosen
        return Button {
            chosen = tab.filter
        } label: {
            HStack(spacing: 6) {
                IconView(icon: tab.filter.icon, size: iconSize)
                    .foregroundStyle(on ? Palette.tinta : Palette.gris)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(tab.filter.label)
                        .font(.ui(14, .medium, relativeTo: .subheadline))
                        .foregroundStyle(on ? Palette.tinta : Palette.gris)
                    if let count = tab.count {
                        Text(count, format: .number)
                            .font(.ui(12, relativeTo: .caption))
                            .monospacedDigit()
                            .foregroundStyle(Palette.gris)
                    }
                }
            }
            .padding(.horizontal, 8)
            .frame(minHeight: 40)
            .overlay(alignment: .bottom) {
                Rectangle().fill(on ? Palette.tinta : Color.clear).frame(height: 2)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(tab.count.map { Text("\(tab.filter.label), \($0)", comment: "A type tab for VoiceOver: the type, then how many items") }
                            ?? Text(tab.filter.label))
        .accessibilityAddTraits(on ? [.isSelected] : [])
        .accessibilityIdentifier("filter-\(String(describing: tab.filter))")
    }
}

/// A row of «Codes», like an authenticator app: the title and user on top,
/// the code large under them with its time blocks. Tapping anywhere on the
/// row copies the current code, with a tap of the Taptic Engine.
struct CodeRow: View {
    let item: ItemInfo
    @EnvironmentObject private var model: AppModel
    @State private var copied = 0
    @State private var showsCheck = false
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        Button(action: copy) {
            HStack(alignment: .top, spacing: 12) {
                Tile(title: item.title, site: item.urls.first)
                VStack(alignment: .leading, spacing: 6) {
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .firstTextBaseline, spacing: 8) { title; user }
                        VStack(alignment: .leading, spacing: 2) { title; user }
                    }
                    LiveCode(id: item.id, title: item.title, style: .detail,
                             fetch: fetchCode,
                             onError: { error in if case KlavError.Locked = error { model.lock() } })
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if !typeSize.isAccessibilitySize {
                    IconView(icon: showsCheck ? .check : .copy)
                        .foregroundStyle(showsCheck ? Palette.tinta : Palette.gris)
                        .frame(width: 36, height: 36)
                        .overlay(Rectangle().strokeBorder(showsCheck ? Palette.tinta : Palette.linea, lineWidth: 1))
                        .frame(maxHeight: .infinity)
                }
            }
            .padding(.vertical, 14)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowButtonStyle())
        .sensoryFeedback(.success, trigger: copied)
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("Copies the code"))
        .accessibilityIdentifier("code-\(item.title)")
    }

    private var title: some View {
        Text(item.title)
            .font(.ui(16, .medium))
            .foregroundStyle(Palette.tinta)
            .lineLimit(typeSize.isAccessibilitySize ? 2 : 1)
    }

    @ViewBuilder private var user: some View {
        if let username = item.username, !username.isEmpty {
            Text(username)
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .lineLimit(1)
        }
    }

    /// Asks klav-core for the code now (the one on screen, or the next one
    /// at the edge of a period) and copies it.
    private func copy() {
        let fetch = fetchCode
        let id = item.id
        Task {
            do {
                let code = try await fetch(id).code
                model.copy(code)
                copied += 1
                showsCheck = true
                try? await Task.sleep(for: .seconds(1.5))
                showsCheck = false
            } catch KlavError.Locked {
                model.lock()
            } catch {
                model.show(Toast(text: describe(error)))
            }
        }
    }

    private var fetchCode: @Sendable (String) async throws -> TotpInfo {
        let service = model.service
        return { id in
            guard let service else { throw CancellationError() }
            return try await service.run { core, _ in try core.totp(id: id) }
        }
    }
}
