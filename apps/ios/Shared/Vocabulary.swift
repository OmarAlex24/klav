import Foundation

// Words the interface uses for vault things, from the string catalog (as
// the browser extension's `ui/strings.ts`).

extension Kind {
    /// What the person calls this kind of item.
    var label: String {
        switch self {
        case .login: return String(localized: "kind.login", defaultValue: "Login", comment: "Kind of item")
        case .card: return String(localized: "Card", comment: "Kind of item")
        case .identity: return String(localized: "Identity", comment: "Kind of item")
        case .sshKey: return String(localized: "SSH key", comment: "Kind of item")
        case .file: return String(localized: "File", comment: "Kind of item")
        case .totp: return String(localized: "One-time code", comment: "Kind of item")
        case .note: return String(localized: "Secure note", comment: "Kind of item")
        case .apiKey: return String(localized: "API key", comment: "Kind of item")
        }
    }
}

extension Kind {
    /// The kind next to the vault in an item's header, as the extension
    /// says it ("Login · Personal / General").
    var shortName: String {
        switch self {
        case .login: return String(localized: "Login", comment: "Kind of item, short, before the vault")
        case .card: return String(localized: "Card", comment: "Kind of item, short, before the vault")
        case .identity: return String(localized: "Address", comment: "Kind of item, short, before the vault")
        case .sshKey: return String(localized: "SSH key", comment: "Kind of item, short, before the vault")
        case .file: return String(localized: "File", comment: "Kind of item, short, before the vault")
        case .totp: return String(localized: "Code", comment: "Kind of item, short, before the vault")
        case .note: return String(localized: "Note", comment: "Kind of item, short, before the vault")
        case .apiKey: return String(localized: "API key", comment: "Kind of item, short, before the vault")
        }
    }

    /// The kind at the end of a list row, small in Geist Mono.
    var tag: String {
        switch self {
        case .login: return String(localized: "login", comment: "Kind of item, small tag at the end of a row")
        case .card: return String(localized: "card", comment: "Kind of item, small tag at the end of a row")
        case .identity: return String(localized: "address", comment: "Kind of item, small tag at the end of a row")
        case .sshKey: return String(localized: "ssh key", comment: "Kind of item, small tag at the end of a row")
        case .file: return String(localized: "file", comment: "Kind of item, small tag at the end of a row")
        case .totp: return String(localized: "code", comment: "Kind of item, small tag at the end of a row")
        case .note: return String(localized: "note", comment: "Kind of item, small tag at the end of a row")
        case .apiKey: return String(localized: "api key", comment: "Kind of item, small tag at the end of a row")
        }
    }

    /// Logins and code items may show a live one-time code in their row.
    var mayHaveCode: Bool { self == .login || self == .totp }

    /// The kind's line icon, the same in the Mac's sidebar, the iPhone's
    /// type tabs and the extension's (`kindIcon` in `kit.ts`).
    var icon: Icon {
        switch self {
        case .login: return .field
        case .totp: return .timer
        case .card: return .card
        case .note: return .page
        case .apiKey: return .braces
        case .sshKey: return .prompt
        case .identity: return .house
        case .file: return .file
        }
    }
}

extension ItemInfo {
    /// The line under the title in the vault list: the user name, else
    /// the site; nothing for the rest (the kind is at the end of the row).
    var listSubtitle: String? {
        if let username, !username.isEmpty { return username }
        if let url = urls.first, let host = URL(string: url)?.host() { return host }
        return nil
    }

    /// The line under the title: the user name, else the site, else the kind.
    var subtitle: String {
        if let username, !username.isEmpty { return username }
        if let url = urls.first, let host = URL(string: url)?.host() { return host }
        return kind.label
    }
}

/// The names of klav-core's template fields, keyed by field name: the
/// template's English label and the name to show (a label the person
/// changed is shown as is).
private func knownField(_ name: String) -> (english: String, shown: String)? {
    switch name {
    case "username": return ("Username", String(localized: "Username", comment: "Field name"))
    case "password": return ("Password", String(localized: "Password", comment: "Field name"))
    case "totp": return ("One-time password", String(localized: "One-time password", comment: "Field name"))
    case "cardholder": return ("Cardholder name", String(localized: "Cardholder name", comment: "Field name"))
    case "number": return ("Number", String(localized: "Number", comment: "Field name"))
    case "expiry": return ("Expiry date", String(localized: "Expiry date", comment: "Field name"))
    case "cvv": return ("Verification code", String(localized: "Verification code", comment: "Field name"))
    case "pin": return ("PIN", String(localized: "PIN", comment: "Field name"))
    case "first_name": return ("First name", String(localized: "First name", comment: "Field name"))
    case "last_name": return ("Last name", String(localized: "Last name", comment: "Field name"))
    case "email": return ("E-mail", String(localized: "E-mail", comment: "Field name"))
    case "phone": return ("Phone", String(localized: "Phone", comment: "Field name"))
    case "address": return ("Address", String(localized: "Address", comment: "Field name"))
    case "city": return ("City", String(localized: "City", comment: "Field name"))
    case "region": return ("State / region", String(localized: "State / region", comment: "Field name"))
    case "postal_code": return ("Postal code", String(localized: "Postal code", comment: "Field name"))
    case "country": return ("Country", String(localized: "Country", comment: "Field name"))
    case "birth_date": return ("Birth date", String(localized: "Birth date", comment: "Field name"))
    case "private_key": return ("Private key", String(localized: "Private key", comment: "Field name"))
    case "public_key": return ("Public key", String(localized: "Public key", comment: "Field name"))
    case "fingerprint": return ("Fingerprint", String(localized: "Fingerprint", comment: "Field name"))
    case "passphrase": return ("Passphrase", String(localized: "Passphrase", comment: "Field name"))
    case "api_key": return ("API key", String(localized: "API key", comment: "Field name"))
    case "key_id": return ("Key ID", String(localized: "Key ID", comment: "Field name"))
    case "base_url": return ("Base URL", String(localized: "Base URL", comment: "Field name"))
    case "expires": return ("Expires", String(localized: "Expires", comment: "Field name"))
    default: return nil
    }
}

/// The name to show for a field.
func fieldName(name: String, label: String) -> String {
    if let known = knownField(name), label.isEmpty || label == known.english || label == name {
        return known.shown
    }
    return label.isEmpty ? name : label
}

extension FieldInfo {
    var displayName: String { fieldName(name: name, label: label) }
}

/// `https://github.com/login` → `github.com`.
func displayHost(_ url: String) -> String {
    URL(string: url)?.host() ?? url
}
