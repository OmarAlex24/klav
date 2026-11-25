import SwiftUI

/// Pieces of the requests of agents that the iPhone and the Mac share:
/// the words, the card with its blue band, the boxes and the chips.

/// What an agent wrote (its note, a reason, a site), as the views show it
/// (ADR 0033 T136): one line, without control or invisible characters
/// (bidi marks included), cut short. And the start of its ID, shown with
/// its name, so two agents with one name are told apart.
enum AgentText {
    static func line(_ text: String, max: Int = 120) -> String {
        let line = text.components(separatedBy: .newlines).joined(separator: " ")
            .unicodeScalars.filter { !$0.properties.isDefaultIgnorableCodePoint && $0.properties.generalCategory != .control }
        let flat = String(String.UnicodeScalarView(line))
        return flat.count > max ? String(flat.prefix(max - 1)) + "…" : flat
    }

    /// «3f2a9c01», the first eight characters of an agent's ID.
    static func idPrefix(_ id: String) -> String { String(id.prefix(8)) }
}

/// A request could not go ahead.
enum RequestError: Error {
    /// Face ID, Touch ID or the device's code did not confirm.
    case notConfirmed
    /// A task card with every box cleared.
    case nothingChecked
    /// A security card (ADR 0049 §5.4, T260): nothing on it is decided.
    case securityCard
}

/// What an agent wants to do, as the extension's popup says it.
enum RequestWords {
    /// "Wants to fill GitHub (password)": `title` is the target's name
    /// (with `Bold.mark(0)` in it for `sentence`).
    static func wants(_ permission: String, _ title: String) -> String {
        switch permission {
        case "list": return String(localized: "Wants to see the list of \(title)")
        case "fill": return String(localized: "Wants to fill \(title)")
        case "inject": return String(localized: "Wants to use \(title)")
        case "totp": return String(localized: "Wants the one-time code for \(title)")
        case "reveal": return String(localized: "Wants to see the value of \(title)")
        case "create": return String(localized: "Wants to create in \(title)")
        case "update": return String(localized: "Wants to change \(title)")
        case "delete": return String(localized: "Wants to delete \(title)")
        case "passkey": return String(localized: "Wants to sign in to \(title) with your passkey")
        case "rotate": return String(localized: "Wants to change the password of \(title)")
        default: return String(localized: "Wants \(permission) \(title)")
        }
    }

    /// `klav://Vault/Project/Title/field` as a title and where it lives.
    static func target(_ target: String) -> (title: String, where: String?) {
        guard target.hasPrefix("klav://") else { return (target, nil) }
        let parts = target.dropFirst("klav://".count)
            .split(separator: "/", omittingEmptySubsequences: false)
            .map { String($0).removingPercentEncoding ?? String($0) }
        guard parts.count >= 3, !parts[2].isEmpty else {
            return (parts.joined(separator: " / "), nil)
        }
        let title = parts.count > 3 && !parts[3].isEmpty ? "\(parts[2]) (\(parts[3]))" : parts[2]
        let place = parts[0..<2].filter { !$0.isEmpty }.joined(separator: " / ")
        return (title, place.isEmpty ? nil : place)
    }

    /// "expires in 4 min", counted up so that 10 s left still reads "1 min".
    static func remaining(until ms: Int64, now: Date = Date()) -> String {
        let seconds = Double(ms) / 1000 - now.timeIntervalSince1970
        if seconds <= 0 { return String(localized: "already expired") }
        let minutes = Int((seconds / 60).rounded(.up))
        if minutes < 60 { return String(localized: "expires in \(minutes) min") }
        let hours = Int((Double(minutes) / 60).rounded(.down))
        return hours == 1 ? String(localized: "expires in 1 hour") : String(localized: "expires in \(hours) hours")
    }
}

extension RequestError {
    var userMessage: String {
        switch self {
        case .notConfirmed: return String(localized: "It wasn’t confirmed that it’s you. Nothing was approved.")
        case .nothingChecked: return String(localized: "Check at least one permission, or deny the task")
        case .securityCard: return McpWords.securityText
        }
    }
}

func describeRequest(_ error: Error) -> String {
    if let e = error as? RequestError { return e.userMessage }
    return describe(error)
}

/// A request: a band of dither down the left, a line around it and the
/// cross corners. The one a notification opened is outlined in cobalt.
struct AgentCard<Content: View>: View {
    var highlighted = false
    /// A running task: how much of its time is spent (0…1). The band
    /// empties from the top, in steps of the dither's pixel.
    var spent: Double?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) { content }
            .padding(.vertical, 14)
            .padding(.leading, 54)
            .padding(.trailing, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            // The band runs the card's full height, whatever its text.
            .background(alignment: .leading) {
                DitherView(kind: .band, palette: .blue, pixel: 3)
                    .overlay(alignment: .top) {
                        if let spent {
                            GeometryReader { geo in
                                VStack(spacing: 0) {
                                    Rectangle().fill(Palette.niebla)
                                        .frame(height: (geo.size.height * spent / 3).rounded() * 3)
                                    Rectangle().fill(Palette.cobalto).frame(height: 1)
                                }
                            }
                            .accessibilityHidden(true)
                        }
                    }
                    .frame(width: 40)
            }
            .background(Palette.papel)
            .overlay(
                Rectangle().strokeBorder(highlighted ? Palette.cobalto : Palette.linea,
                                         lineWidth: highlighted ? 1.5 : 1)
            )
            .crossCorners()
            .accessibilityElement(children: .contain)
    }
}

/// Marks where a name goes in a sentence from the string catalog
/// (private-use characters, as the extension's `tNodes`).
enum Bold {
    static func mark(_ index: Int) -> String { "\u{E000}\(index)\u{E001}" }
}

/// A sentence with names in semibold, without `Text +`: each
/// `Bold.mark(n)` in `text` becomes `names[n]`.
func sentence(_ text: String, bold names: [String], size: CGFloat = 15) -> Text {
    var out = AttributedString()
    func add(_ piece: some StringProtocol, bold: Bool) {
        guard !piece.isEmpty else { return }
        var run = AttributedString(String(piece))
        run.font = .ui(size, bold ? .semibold : .regular)
        out += run
    }
    var rest = Substring(text)
    while let open = rest.firstIndex(of: "\u{E000}"),
          let close = rest[open...].firstIndex(of: "\u{E001}"),
          let index = Int(rest[rest.index(after: open)..<close]), names.indices.contains(index) {
        add(rest[..<open], bold: false)
        add(names[index], bold: true)
        rest = rest[rest.index(after: close)...]
    }
    add(rest, bold: false)
    return Text(out)
}

/// When a request stops waiting, kept current.
struct Expires: View {
    let at: Int64

    var body: some View {
        TimelineView(.periodic(from: .now, by: 20)) { context in
            Text(RequestWords.remaining(until: at, now: context.date).capitalizedFirst)
                .font(.ui(12, relativeTo: .caption))
                .foregroundStyle(Palette.gris)
        }
    }
}

/// A square choice: ink line and a check when chosen, grey when not.
struct Chip: View {
    let text: String
    let on: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if on { IconView(icon: .check) }
                Text(text).lineLimit(1)
            }
            .font(.ui(14, on ? .medium : .regular, relativeTo: .subheadline))
            .foregroundStyle(on ? Palette.tinta : Palette.gris)
            .padding(.horizontal, 12)
            .frame(minHeight: 40)
            .overlay(Rectangle().strokeBorder(on ? Palette.tinta : Palette.linea, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

/// Lays its views out in rows, wrapping when a row is full.
struct Flow: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, row: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: width, height: nil))
            if x > 0, x + size.width > width {
                y += row + spacing
                x = 0
                row = 0
            }
            x += size.width + spacing
            row = max(row, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: proposal.width ?? widest, height: y + row)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, row: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: bounds.width, height: nil))
            if x > bounds.minX, x + size.width > bounds.maxX {
                y += row + spacing
                x = bounds.minX
                row = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(width: min(size.width, bounds.width), height: size.height))
            x += size.width + spacing
            row = max(row, size.height)
        }
    }
}

extension String {
    var capitalizedFirst: String {
        guard let first else { return self }
        return first.uppercased() + dropFirst()
    }
}

/// A square box: checked in ink, a dash when some of an item's
/// permissions are checked, mist and a light line when it cannot be.
struct CheckBox: View {
    let state: TaskEdits.State
    var enabled = true

    var body: some View {
        ZStack {
            Rectangle().fill(!enabled ? Palette.niebla : state == .on ? Palette.boton : Palette.papel)
            Rectangle().strokeBorder(enabled ? Palette.tinta : Palette.linea, lineWidth: 1)
            if enabled && state == .on {
                IconView(icon: .check, size: 16).foregroundStyle(Palette.botonTexto)
            } else if enabled && state == .mixed {
                Rectangle().fill(Palette.tinta).frame(width: 10, height: 2)
            }
        }
        .frame(width: 22, height: 22)
        .accessibilityHidden(true)
    }
}

/// A line with a box at its end; the whole line toggles. One element for
/// VoiceOver, with its own label.
struct CheckRow<Content: View>: View {
    let state: TaskEdits.State
    var enabled = true
    let label: String
    let action: () -> Void
    @ViewBuilder var content: Content

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                content.frame(maxWidth: .infinity, alignment: .leading)
                CheckBox(state: state, enabled: enabled)
            }
            .frame(minHeight: 30)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        // The button is the one element: its own label replaces the texts
        // inside it.
        .accessibilityLabel(label)
        .accessibilityValue(state == .on ? Text("On") : state == .mixed ? Text("Mixed") : Text("Off"))
        .accessibilityAddTraits(.isToggle)
    }
}


/// A block that groups data: lines above and below, rows in between, and
/// the cross corners.
struct FieldBlock<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .overlay(alignment: .top) { Rule() }
            .overlay(alignment: .bottom) { Rule() }
            .crossCorners()
    }
}

extension AgentItem: Identifiable {}
extension ApprovalItem: Identifiable {}
extension TaskItem: Identifiable {}
extension ItemInfo: Identifiable {}

/// A small tag with a line around it, in the color of what it says: an
/// outcome, an alert, «Not verified yet» (ADR 0033 §8.1).
struct Tag: View {
    let text: String
    let color: Color

    var body: some View {
        Text(verbatim: text)
            .font(.ui(11, .medium, relativeTo: .caption2))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .frame(minHeight: 20)
            .overlay(Rectangle().strokeBorder(color.opacity(0.7), lineWidth: 1))
    }
}

/// A filter as a menu, drawn like a chip: its name, and what is chosen.
struct FilterMenu<Content: View>: View {
    let title: String
    let chosen: [String]
    @ViewBuilder var content: Content

    var body: some View {
        Menu {
            content
        } label: {
            HStack(spacing: 6) {
                Text(verbatim: chosen.isEmpty ? title : "\(title): \(chosen.sorted().joined(separator: ", "))")
                    .lineLimit(1)
                Text(verbatim: "▾").font(.ui(10)).accessibilityHidden(true)
            }
            .font(.ui(14, chosen.isEmpty ? .regular : .medium, relativeTo: .subheadline))
            .foregroundStyle(chosen.isEmpty ? Palette.gris : Palette.tinta)
            .padding(.horizontal, 12)
            .frame(minHeight: 40)
            .overlay(Rectangle().strokeBorder(chosen.isEmpty ? Palette.linea : Palette.tinta, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
    }
}

extension ActivityWords {
    /// Who did what: an agent's name in cobalt, the start of its ID, then
    /// what it did (§8.1, T136); or what you did, then the start of the ID
    /// of the agent it was about.
    static func sentence(_ e: LogEntryInfo, size: CGFloat) -> Text {
        let id = Text(verbatim: e.agentId.map { " " + AgentText.idPrefix($0) } ?? "")
            .font(.mono(size - 2)).foregroundColor(Palette.gris)
        guard isAgent(e) else {
            return Text(verbatim: yours(e)).font(.ui(size)).foregroundColor(Palette.tinta) + id
        }
        let name = Text(verbatim: actor(e)).font(.ui(size, .medium)).foregroundColor(Palette.cobalto)
        let what = Text(verbatim: " " + did(e)).font(.ui(size)).foregroundColor(Palette.tinta)
        // An MCP call (ADR 0049 §6): the caller and the tool are the
        // proxy's word, marked as such (T136).
        if e.action == "agent.access", McpWords.isMcp(e) {
            let mark = Text(verbatim: " (" + McpWords.accordingToProxy + ")")
                .font(.ui(size - 2)).foregroundColor(Palette.gris)
            return name + id + what + mark
        }
        return name + id + what
    }
}
