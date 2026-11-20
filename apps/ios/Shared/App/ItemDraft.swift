import Foundation

/// A field the item editor shows (the iPhone's `ItemEditor` and the Mac's
/// `ItemEditorSheet`).
struct FieldSpec: Identifiable, Equatable {
    let name: String
    let label: String
    var secret = false
    var generate = false
    var placeholder = ""
    var original: String?

    var id: String { name }
}

/// What the item editor does, the same on the iPhone and the Mac: the
/// fields of each kind, and what goes to `create_item` or `edit_item`.
/// Secret values are never pre-filled: an empty secret field keeps what
/// the item has.
enum ItemDraft {
    /// The kinds the apps can create (klav-core's templates).
    static let creatable: [Kind] = [.login, .apiKey, .card, .note]

    /// The fields of a new item of `kind`.
    static func templateFields(_ kind: Kind) -> [FieldSpec] {
        switch kind {
        case .login:
            return [
                FieldSpec(name: "username", label: String(localized: "Username", comment: "Field name"), placeholder: String(localized: "you@example.com")),
                FieldSpec(name: "password", label: String(localized: "Password", comment: "Field name"), secret: true, generate: true),
                FieldSpec(name: "totp", label: String(localized: "One-time code secret (optional)"), secret: true,
                          placeholder: "JBSW Y3DP …"),
            ]
        case .apiKey:
            return [FieldSpec(name: "api_key", label: String(localized: "API key", comment: "Field name"), secret: true)]
        case .card:
            return [
                FieldSpec(name: "cardholder", label: String(localized: "Cardholder name", comment: "Field name")),
                FieldSpec(name: "number", label: String(localized: "Number", comment: "Field name"), secret: true),
                FieldSpec(name: "expiry", label: String(localized: "Expiry date", comment: "Field name"), placeholder: String(localized: "YYYY-MM")),
                FieldSpec(name: "cvv", label: String(localized: "Verification code", comment: "Field name"), secret: true),
            ]
        default:
            return []
        }
    }

    /// The fields of an item being edited, files aside. A filled secret
    /// says «Unchanged» until the person types a new value.
    static func editFields(_ detail: ItemDetail) -> [FieldSpec] {
        detail.fields.filter { $0.kind != .file }.map { field in
            FieldSpec(name: field.name, label: field.displayName, secret: field.secret,
                      generate: field.kind == .password,
                      placeholder: field.secret && field.filled ? String(localized: "Unchanged") : "",
                      original: field.value)
        }
    }

    /// What the editor fills in when it opens on an item: its plain
    /// values. Secrets stay empty.
    static func plainValues(_ detail: ItemDetail) -> [String: String] {
        var values: [String: String] = [:]
        for field in detail.fields where !field.secret {
            values[field.name] = field.value ?? ""
        }
        return values
    }

    /// The kind's name on the editor's segments.
    static func shortLabel(_ kind: Kind) -> String {
        switch kind {
        case .login: return String(localized: "Login", comment: "Kind of item, short, before the vault")
        case .apiKey: return String(localized: "API key", comment: "Kind of item, short, before the vault")
        case .card: return String(localized: "Card", comment: "Kind of item, short, before the vault")
        case .note: return String(localized: "Note", comment: "Kind of item, short, before the vault")
        default: return kind.shortName
        }
    }

    /// `github.com` → `https://github.com`; empty → nil.
    static func normalizedSite(_ text: String) -> String? {
        let s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        return s.contains("://") ? s : "https://" + s
    }

    /// A new item: the fields the person filled, its site if it is a
    /// login, and its notes.
    static func newItem(kind: Kind, title: String, project: ProjectInfo?, specs: [FieldSpec],
                        typed: [String: String], site: String, notes: String) -> NewItemInput {
        let url = normalizedSite(site)
        return NewItemInput(
            kind: kind, title: title.trimmingCharacters(in: .whitespaces),
            vaultId: project?.vaultId, projectId: project?.id,
            fields: specs.compactMap { spec in
                let value = typed[spec.name] ?? ""
                return value.isEmpty ? nil : FieldEdit(name: spec.name, value: value)
            },
            urls: kind == .login ? (url.map { [$0] } ?? []) : [],
            notes: notes.isEmpty ? nil : notes)
    }

    /// What changed on an item: a secret only if the person typed one, a
    /// plain field only if it differs, the title only if it changed, the
    /// site to add, and the notes only if they were opened and changed (or
    /// written on an item without any).
    static func edit(of detail: ItemDetail, title: String, specs: [FieldSpec], typed: [String: String],
                     site: String, notes: String, notesBefore: String?) -> ItemEdit {
        let cleanTitle = title.trimmingCharacters(in: .whitespaces)
        let set = specs.compactMap { spec -> FieldEdit? in
            let value = typed[spec.name] ?? ""
            if spec.secret { return value.isEmpty ? nil : FieldEdit(name: spec.name, value: value) }
            return value == (spec.original ?? "") ? nil : FieldEdit(name: spec.name, value: value)
        }
        let newNotes: String? = notesBefore != nil
            ? (notes == notesBefore ? nil : notes)
            : (notes.isEmpty ? nil : notes)
        return ItemEdit(title: cleanTitle == detail.info.title ? nil : cleanTitle,
                        set: set, addUrls: normalizedSite(site).map { [$0] } ?? [], notes: newNotes)
    }
}

/// Whether a title is taken in a project, the rule klav-client uses to
/// refuse a new item (`titled`): spaces around aside, ASCII case aside.
func titleTaken(_ title: String, in projectId: String?, items: [ItemInfo]) -> Bool {
    func key(_ text: String) -> String {
        String(text.trimmingCharacters(in: .whitespacesAndNewlines).map { $0.isASCII ? Character($0.lowercased()) : $0 })
    }
    let wanted = key(title)
    guard !wanted.isEmpty, let projectId else { return false }
    return items.contains { $0.projectId == projectId && key($0.title) == wanted }
}
