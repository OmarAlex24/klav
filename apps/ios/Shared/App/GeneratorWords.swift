import SwiftUI

// The generator's words and colours, the same on the iPhone and the Mac
// (ADR 0022 §1–§2, as in the extension).

enum GeneratorWords {
    /// What the generator says about the site's rules, if anything.
    static func rulesNote(_ g: GeneratedPassword, kind: GeneratorType, site: String?) -> String? {
        if g.fallback == "unreadable" { return String(localized: "The site’s rules could not be read, so this is a random password.") }
        if g.fallback == "impossible" { return String(localized: "No password fits the site’s rules, so this is a random password.") }
        var parts: [String] = []
        // Without a site (from Settings) there are no rules to speak of.
        if kind == .smart, site != nil {
            if let domain = g.rulesDomain {
                parts.append(String(localized: "Follows the rules of \(domain)."))
            } else {
                parts.append(String(localized: "No rules from the site: 20 characters."))
            }
        }
        if g.limited { parts.append(String(localized: "The site does not allow a stronger one.")) }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }
}

/// Letters in ink, digits in grey, each symbol on a mist cell (G10).
/// A PIN (only digits) stays in ink: grey alone reads like a placeholder.
func colored(_ value: String) -> AttributedString {
    var out = AttributedString()
    let pin = value.allSatisfy { $0.isASCII && $0.isNumber }
    for ch in value {
        var piece = AttributedString(String(ch))
        if ch.isASCII && (ch.isLetter || (pin && ch.isNumber)) {
            piece.foregroundColor = Palette.tinta
        } else if ch.isASCII && ch.isNumber {
            piece.foregroundColor = Palette.gris
        } else {
            piece.foregroundColor = Palette.tinta
            piece.backgroundColor = Palette.niebla
        }
        out.append(piece)
    }
    return out
}

func strengthName(_ strength: String) -> String {
    switch strength {
    case "weak": return String(localized: "Weak")
    case "fair": return String(localized: "Fair")
    case "strong": return String(localized: "Strong")
    default: return String(localized: "Very strong")
    }
}

extension GeneratorType {
    static let all: [GeneratorType] = [.smart, .random, .memorable, .pin]

    var key: String {
        switch self {
        case .smart: return "smart"
        case .random: return "random"
        case .memorable: return "memorable"
        case .pin: return "pin"
        }
    }

    init?(key: String) {
        guard let found = GeneratorType.all.first(where: { $0.key == key }) else { return nil }
        self = found
    }

    var name: LocalizedStringKey {
        switch self {
        case .smart: return "Smart"
        case .random: return "Random"
        case .memorable: return "Memorable"
        case .pin: return "PIN"
        }
    }
}

extension Binding {
    /// The same binding, calling `action` after each change.
    func onChange(_ action: @escaping () -> Void) -> Binding<Value> {
        Binding(get: { wrappedValue }, set: { wrappedValue = $0; action() })
    }
}
