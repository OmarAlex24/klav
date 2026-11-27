import Foundation

// Environments in the apps (ADR 0032 §6): what the iPhone and the Mac share
// of an environment's page. The rules a name follows, the draft of a
// variable and the edit it becomes, the words of an origin, and which
// values are on screen. The engines do the rest: `klavd` asks for Touch ID
// on the Mac, and `KlavCore` asks for Face ID on the iPhone, every time in
// a protected environment. Importing a `.env` stays the CLI's (§6).

enum EnvironmentRules {
    /// A variable's name: letters, digits and `_`, not starting with a
    /// digit, up to 128, case-sensitive (ADR 0032 §1).
    static func isVariableName(_ name: String) -> Bool {
        name.range(of: #"^[A-Za-z_][A-Za-z0-9_]{0,127}$"#, options: .regularExpression) != nil
    }

    /// An environment's name: what `--env` and `klav://` write without
    /// quotes.
    static func isEnvironmentName(_ name: String) -> Bool {
        name.range(of: #"^[a-z0-9][a-z0-9_-]{0,63}$"#, options: .regularExpression) != nil
    }

    /// `production` and `prod` start protected (§3).
    static func protectedByDefault(_ name: String) -> Bool {
        let n = name.trimmingCharacters(in: .whitespaces).lowercased()
        return n == "production" || n == "prod"
    }

    /// A new environment: created, never over one that exists.
    static func create(protected: Bool) -> EnvironmentEditInput {
        EnvironmentEditInput(create: true, mustBeNew: true, protected: protected, set: [], remove: [])
    }

    static func remove(_ name: String) -> EnvironmentEditInput {
        EnvironmentEditInput(create: false, mustBeNew: false, protected: nil, set: [], remove: [name])
    }

    static func protect(_ on: Bool) -> EnvironmentEditInput {
        EnvironmentEditInput(create: false, mustBeNew: false, protected: on, set: [], remove: [])
    }
}

/// The form of a variable: a new one, or a new value for one that exists.
struct VariableDraft: Equatable {
    enum Source: Equatable { case value, reference }

    var name = ""
    var source: Source = .value
    var text = ""

    /// What keeps it from saving, in the interface's language; nil when it
    /// can be saved.
    var problem: String? {
        let name = name.trimmingCharacters(in: .whitespaces)
        if !EnvironmentRules.isVariableName(name) {
            return String(localized: "Letters, digits and _, not starting with a digit (up to 128).",
                          comment: "A variable's name is not valid")
        }
        switch source {
        case .reference where !text.trimmingCharacters(in: .whitespaces).hasPrefix("klav://"):
            return String(localized: "A reference starts with klav://", comment: "A variable's reference is not valid")
        case .value where text.isEmpty:
            return String(localized: "Type a value.", comment: "A variable has no value")
        default:
            return nil
        }
    }

    /// The edit that sets it; nil while `problem` says why not.
    var edit: EnvironmentEditInput? {
        guard problem == nil else { return nil }
        let name = name.trimmingCharacters(in: .whitespaces)
        let variable = switch source {
        case .value: VariableInput(name: name, value: text, reference: nil)
        case .reference: VariableInput(name: name, value: nil, reference: text.trimmingCharacters(in: .whitespaces))
        }
        return EnvironmentEditInput(create: false, mustBeNew: false, protected: nil, set: [variable], remove: [])
    }
}

enum EnvironmentWords {
    /// Where a variable's value comes from: «Its own value», «From Stripe ›
    /// api_key», and «· protected» when that item is.
    static func origin(_ v: VariableInfo) -> String {
        guard v.reference != nil else {
            return String(localized: "Its own value", comment: "A variable that stores its value")
        }
        let from = v.target.map {
            String(localized: "env.from", defaultValue: "From \($0)", comment: "Where a variable's value comes from: «Item › field»")
        }
            ?? String(localized: "From an item this device can’t see", comment: "A variable's reference to an item not on this device")
        return v.targetProtected
            ? String(localized: "\(from) · protected", comment: "A variable's origin, whose item is protected")
            : from
    }

    /// A row's second line: «Personal / acme-api · 3 variables».
    static func row(vault: String, project: String, variables: Int?) -> String {
        guard let variables else { return "\(vault) / \(project)" }
        let count = String(localized: "\(variables) variables", comment: "How many variables an environment has")
        return "\(vault) / \(project) · \(count)"
    }

    /// The notice of a protected environment.
    static var protectedNotice: String {
        String(localized: "Protected: showing or copying a value asks for Touch ID or Face ID every time.",
               comment: "On a protected environment's page")
    }

    /// The notice on the page of an item a protected environment points to.
    static func protectedBy(_ names: [String]) -> String {
        let list = names.map { "“\($0)”" }.joined(separator: ", ")
        return String(localized: "Protected by \(list): showing or copying a value asks for Touch ID or Face ID every time.",
                      comment: "On a protected item's page: the environments that protect it")
    }

    /// What an agent changed since the person last saved it (§3).
    static func agentChanged(_ changes: AgentChangesInfo) -> String {
        let agent = changes.agent ?? String(localized: "An agent", comment: "An agent whose name this device doesn't know")
        let list = changes.variables.joined(separator: ", ")
        return String(localized: "\(agent) changed \(list) since you last saved it. Check them before using them.",
                      comment: "On an environment an agent changed")
    }

    /// What saving said: the items that became protected, or «Saved».
    static func saved(_ saved: EnvironmentSavedInfo) -> String {
        saved.newlyProtected.isEmpty
            ? String(localized: "Saved", comment: "An environment was saved")
            : String(localized: "Now protected: \(saved.newlyProtected.joined(separator: ", "))",
                     comment: "Items a protected environment's new reference protects")
    }

}

/// The values on an environment's page: each shows only while the person
/// keeps it open, and all go when the page closes, Klav locks or the
/// environment reloads.
struct EnvironmentReveal: Equatable {
    private(set) var shown: [String: String] = [:]

    func value(_ name: String) -> String? { shown[name] }
    func isShown(_ name: String) -> Bool { shown[name] != nil }

    mutating func show(_ name: String, _ value: String) { shown[name] = value }
    mutating func hide(_ name: String) { shown[name] = nil }
    mutating func hideAll() { shown = [:] }
}

extension VariableInfo: Identifiable {
    public var id: String { name }
}
