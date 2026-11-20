import Foundation
import Security

/// Reads code signatures: `LiveSignatures` asks Security, the tests pass
/// made-up answers.
protocol CodeSignatures: Sendable {
    /// The team the signature at `url` names, read without checking the
    /// signature: nil when it is ad hoc, unsigned or unreadable.
    func claimedTeam(of url: URL) -> String?
    /// nil when `url`'s signature is valid and satisfies `requirement`;
    /// otherwise, why not.
    func problem(_ url: URL, requirement: String) -> String?
}

struct LiveSignatures: CodeSignatures {
    func claimedTeam(of url: URL) -> String? { HelperSignature.claimedTeam(of: url) }
    func problem(_ url: URL, requirement: String) -> String? { HelperSignature.verify(url, requirement: requirement) }
}

/// T120 (ADR 0027): before setting anything up, the app checks that
/// `klav`, `klavd` and `klav-native-host` in its bundle are signed by
/// Klav's team, each with its own identifier, and that its own seal holds.
/// If not, the setup does nothing: no LaunchAgent, no link, no manifests.
///
/// The team the app's signature names, read without checking it, only
/// picks the path; it is never trusted. An app that names Klav's team is
/// checked against the real requirement (Apple's anchor and the team in
/// the certificate), so a forged name only fails there, and a tampered
/// helper is caught even though it also breaks the app's seal. An app that
/// names another team, or none (ad hoc), is not Klav's build: a release
/// build sets nothing up; a Debug build sets up and says that its helpers
/// are not checked. No setting or variable turns the check off in a
/// release build.
///
/// `klavd` lives in its own bundle, `Helpers/klavd.app`, so that the Touch
/// ID dialog says Klav (ADR 0027, note of 2026-11-05): the check is on that
/// bundle, and `Helpers/klavd` must be the link to its binary that
/// `scripts/macos/embed-helpers.sh` leaves. A static check through the link
/// fails even when the signature is good.
enum HelperSignature {
    static let teamID = "SZ3F58F8LX"
    /// `klavd`'s bundle, in `Contents/Helpers`.
    static let daemonBundle = "klavd.app"
    /// Where `Helpers/klavd` points, relative to `Helpers`.
    static let daemonLinkTarget = "klavd.app/Contents/MacOS/klavd"

    enum Verdict: Equatable {
        /// Klav's team signed the app, its seal holds, and every helper is
        /// the team's.
        case trusted
        /// The app names Klav's team, but part of it fails the check: what
        /// failed. Nothing is set up.
        case untrusted(String)
        /// A release build not signed by Klav's team: the team it names
        /// (nil when ad hoc). Nothing is set up.
        case notTeamSigned(String?)
        /// A Debug build not signed by Klav's team: it sets up, and says
        /// that its helpers are not checked.
        case development

        /// Why nothing may be set up, or nil.
        var refusal: String? {
            switch self {
            case .trusted, .development: return nil
            case .untrusted(let why): return why
            case .notTeamSigned(let team): return team.map { "team \($0)" } ?? "ad hoc"
            }
        }
    }

    /// Only a Debug build sets up without the team's signature.
    static var developmentBuild: Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    /// The requirement every helper (and the team's app) satisfies.
    static func requirement(identifier: String? = nil) -> String {
        let team = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        guard let identifier else { return team }
        return "identifier \"\(identifier)\" and \(team)"
    }

    static func check(helpers: URL, app: URL = Bundle.main.bundleURL,
                      signatures: CodeSignatures = LiveSignatures(),
                      development: Bool = developmentBuild) -> Verdict {
        let claimed = signatures.claimedTeam(of: app)
        guard claimed == teamID else { return development ? .development : .notTeamSigned(claimed) }
        // The helpers first: their own message says more than the app's
        // broken seal, which a tampered helper also causes.
        let signed = [("klav", "klav"), ("klav-native-host", "klav-native-host"), ("klavd", daemonBundle)]
        for (name, file) in signed {
            let url = helpers.appendingPathComponent(file)
            if let problem = signatures.problem(url, requirement: requirement(identifier: "dev.klav.\(name)")) {
                return .untrusted("\(name): \(problem)")
            }
        }
        if let problem = daemonLinkProblem(helpers: helpers) {
            return .untrusted("klavd: \(problem)")
        }
        // Then the app: only its seal covers the LaunchAgent's plist and the
        // klavd link.
        if let problem = signatures.problem(app, requirement: requirement()) {
            return .untrusted("\(app.lastPathComponent): \(problem)")
        }
        return .trusted
    }

    /// nil when `Helpers/klavd` is the link to `klavd.app`'s binary;
    /// otherwise, what is there instead.
    static func daemonLinkProblem(helpers: URL) -> String? {
        let path = helpers.appendingPathComponent("klavd").path
        guard let target = try? FileManager.default.destinationOfSymbolicLink(atPath: path) else {
            return FileManager.default.fileExists(atPath: path) ? String(localized: "not a link") : String(localized: "missing")
        }
        return target == daemonLinkTarget ? nil : "→ \(target)"
    }

    /// The team `url`'s signature names, without checking the signature
    /// (`SecCodeCopySigningInformation` does not validate): it reads even
    /// when the seal is broken. nil when ad hoc or unsigned.
    static func claimedTeam(of url: URL) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let info = info as? [String: Any] else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// nil when `url`'s signature is valid and satisfies `requirement`;
    /// otherwise, why not.
    static func verify(_ url: URL, requirement text: String) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else {
            return String(localized: "missing")
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            return "requirement"
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        let status = SecStaticCodeCheckValidity(code, flags, requirement)
        guard status != errSecSuccess else { return nil }
        return (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    }
}
