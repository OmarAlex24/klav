import SwiftUI

/// The logos of common sites that Klav ships (Simple Icons: CC0 1.0 or no
/// license data, see THIRD-PARTY-NOTICES.md), the same
/// map as the browser extension: `assets/site-icons/site-icons.json`, built
/// by `scripts/site-icons.mjs`. Nothing is ever asked of an icon service:
/// a vault's sites are private (docs/ios.md, "Site icons").
enum SiteIcons {
    private struct Map: Decodable {
        struct Icon: Decodable {
            let domains: [String]
            let path: String
        }
        let icons: [Icon]
    }

    /// Domain → path, read the first time a row asks.
    static let logos: [String: String] = {
        guard let url = Bundle.main.url(forResource: "site-icons", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let map = try? JSONDecoder().decode(Map.self, from: data)
        else { return [:] }
        var logos: [String: String] = [:]
        for icon in map.icons {
            for domain in icon.domains { logos[domain] = icon.path }
        }
        return logos
    }()

    /// `https://www.GitHub.com/login` or `github.com` → `github.com`.
    static func host(_ site: String) -> String? {
        let url = URL(string: site.contains("://") ? site : "https://\(site)")
        guard var host = url?.host()?.lowercased(), !host.isEmpty else { return nil }
        if host.hasPrefix("www.") { host.removeFirst(4) }
        return host.isEmpty ? nil : host
    }

    /// The logo for `host` or the closest parent domain that has one
    /// (`gist.github.com` → GitHub), never a look-alike (`evilgithub.com`).
    static func logo(for host: String, in logos: [String: String] = logos) -> String? {
        var name = Substring(host)
        while true {
            if let path = logos[String(name)] { return path }
            guard let dot = name.firstIndex(of: ".") else { return nil }
            name = name[name.index(after: dot)...]
        }
    }

    /// The logo for an item's site (its first URL), if Klav ships one.
    static func logo(forSite site: String?) -> String? {
        guard let site, let host = host(site) else { return nil }
        return logo(for: host)
    }
}

/// A Simple Icons path on its 24-point grid. The map only has absolute
/// M, L, C, Q and Z, numbers written as short as they go ("M.5-.25L12 4Z",
/// "1.5.5" is 1.5 then .5), so this is the whole parser.
enum LogoPath {
    private static var cache: [String: Path] = [:]
    private static let lock = NSLock()

    /// Commands and numbers, in order. Nil if the path has anything else.
    static func tokens(_ d: String) -> [Token]? {
        var out: [Token] = []
        var i = d.startIndex
        while i < d.endIndex {
            let c = d[i]
            if "MLCQZ".contains(c) {
                out.append(.command(c))
                i = d.index(after: i)
            } else if c == " " || c == "," {
                i = d.index(after: i)
            } else if c == "-" || c == "." || c.isNumber {
                var j = d.index(after: i)
                var dot = c == "."
                while j < d.endIndex {
                    let n = d[j]
                    if n.isNumber {
                        j = d.index(after: j)
                    } else if n == ".", !dot {
                        dot = true
                        j = d.index(after: j)
                    } else {
                        break
                    }
                }
                guard let value = Double(d[i..<j]) else { return nil }
                out.append(.number(value))
                i = j
            } else {
                return nil
            }
        }
        return out
    }

    enum Token: Equatable {
        case command(Character)
        case number(Double)
    }

    /// The path in 24×24 units, or nil if it does not parse.
    static func parse(_ d: String) -> Path? {
        lock.lock()
        defer { lock.unlock() }
        if let path = cache[d] { return path }
        guard let tokens = tokens(d) else { return nil }
        var path = Path()
        var command: Character?
        var numbers: [Double] = []
        func flush() -> Bool {
            guard let command else { return numbers.isEmpty }
            // Every path starts with a move.
            if path.isEmpty, command != "M" { return false }
            let count: Int
            switch command {
            case "M", "L": count = 2
            case "Q": count = 4
            case "C": count = 6
            case "Z": count = 0
            default: return false
            }
            if count == 0 {
                guard numbers.isEmpty else { return false }
                path.closeSubpath()
                return true
            }
            guard !numbers.isEmpty, numbers.count % count == 0 else { return false }
            var k = 0
            var first = true
            while k < numbers.count {
                let n = numbers[k..<(k + count)].map { CGFloat($0) }
                switch command {
                case "M" where first: path.move(to: CGPoint(x: n[0], y: n[1]))
                case "M", "L": path.addLine(to: CGPoint(x: n[0], y: n[1]))
                case "Q": path.addQuadCurve(to: CGPoint(x: n[2], y: n[3]), control: CGPoint(x: n[0], y: n[1]))
                default:
                    path.addCurve(to: CGPoint(x: n[4], y: n[5]),
                                  control1: CGPoint(x: n[0], y: n[1]), control2: CGPoint(x: n[2], y: n[3]))
                }
                first = false
                k += count
            }
            return true
        }
        for token in tokens {
            switch token {
            case .command(let c):
                guard flush() else { return nil }
                command = c
                numbers = []
            case .number(let value):
                guard command != nil else { return nil }
                numbers.append(value)
            }
        }
        guard flush(), !path.isEmpty else { return nil }
        cache[d] = path
        return path
    }
}

/// A site's logo, scaled from its 24-point grid to the frame.
struct LogoShape: Shape {
    let d: String

    func path(in rect: CGRect) -> Path {
        guard let path = LogoPath.parse(d) else { return Path() }
        let scale = min(rect.width, rect.height) / 24
        return path.applying(CGAffineTransform(scaleX: scale, y: scale)
            .concatenating(CGAffineTransform(translationX: rect.minX, y: rect.minY)))
    }
}
