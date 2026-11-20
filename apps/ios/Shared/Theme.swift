import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// Klav's tokens (docs/diseno-visual §2), the same as the browser
/// extension's `ui/klav.css`: white paper and near-black ink, thin lines.
/// Blue means something: agents and the one-time code's time. Light and
/// dark follow the system.
enum Palette {
    /// Text, the primary button, the edge of what floats.
    static let tinta = tone(0x09090B, 0xFAFAFA)
    /// The background.
    static let papel = tone(0xFFFFFF, 0x09090B)
    /// A pressed row, soft fills.
    static let niebla = tone(0xF4F4F5, 0x18181B)
    /// Borders and dividers.
    static let linea = tone(0xE4E4E7, 0x27272A)
    /// Cross corners.
    static let cruz = tone(0xA1A1AA, 0x52525B)
    /// Secondary text.
    static let gris = tone(0x71717A, 0xA1A1AA)
    /// The dither's dark tone.
    static let marino = tone(0x0D1466, 0x0A0F4D)
    /// Agents, the code's time, focus.
    static let cobalto = tone(0x2337FF, 0x4555FF)
    /// Deny, errors, "They don’t match".
    static let rojo = tone(0xE5484D, 0xF2555A)
    /// The primary button: ink on paper, inverted in dark.
    static let boton = tinta
    static let botonTexto = papel

    #if canImport(UIKit)
    private static func tone(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            uiColor(traits.userInterfaceStyle == .dark ? dark : light)
        })
    }

    static func uiColor(_ hex: UInt32) -> UIColor {
        UIColor(red: CGFloat((hex >> 16) & 255) / 255, green: CGFloat((hex >> 8) & 255) / 255,
                blue: CGFloat(hex & 255) / 255, alpha: 1)
    }
    #else
    /// The same tones on macOS, following the window's appearance.
    private static func tone(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return nsColor(isDark ? dark : light)
        })
    }

    static func nsColor(_ hex: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255, green: CGFloat((hex >> 8) & 255) / 255,
                blue: CGFloat(hex & 255) / 255, alpha: 1)
    }
    #endif
}

// MARK: - Type

extension Font {
    /// Geist, the whole interface. The variable font's named instances
    /// (400, 500, 600) are reached by PostScript name. Scales with Dynamic
    /// Type relative to `style`.
    static func ui(_ size: CGFloat, _ weight: Font.Weight = .regular, relativeTo style: TextStyle = .body) -> Font {
        let name: String
        switch weight {
        case .semibold, .bold, .heavy, .black: name = "Geist-SemiBold"
        case .medium: name = "Geist-Medium"
        default: name = "Geist-Regular"
        }
        return .custom(name, size: size, relativeTo: style)
    }

    /// Departure Mono: only one-time codes and the six pairing words.
    static func pixel(_ size: CGFloat, relativeTo style: TextStyle = .title) -> Font {
        .custom("DepartureMono-Regular", size: size, relativeTo: style)
    }

    /// Geist Mono: `klav://` references and an item's kind, small and grey.
    static func mono(_ size: CGFloat = 12, relativeTo style: TextStyle = .caption) -> Font {
        .custom("GeistMono-Regular", size: size, relativeTo: style)
    }
}

/// A title: Geist 600 with negative tracking (≈ −0.045 em).
///
/// Like `Text`, a literal is a key of the string catalog and a `String`
/// (an item's title) is shown as is.
struct Title: View {
    let text: Text
    var size: CGFloat = 26

    init(_ key: LocalizedStringKey, size: CGFloat = 26) {
        self.text = Text(key)
        self.size = size
    }

    // Like Text: a literal takes the key overload above.
    @_disfavoredOverload
    init<S: StringProtocol>(_ string: S, size: CGFloat = 26) {
        self.text = Text(string)
        self.size = size
    }

    var body: some View {
        text
            .font(.ui(size, .semibold, relativeTo: .title))
            .tracking(-0.045 * size)
            .foregroundStyle(Palette.tinta)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isHeader)
    }
}

/// The mark and the name, as in the extension's bar.
struct Wordmark: View {
    var size: CGFloat = 19

    var body: some View {
        HStack(spacing: size * 0.4) {
            KeyGlyphShape()
                .fill(Palette.tinta)
                .frame(width: size, height: size * 5 / 8)
            Text(verbatim: "klav")
                .font(.ui(size, .semibold, relativeTo: .headline))
                .tracking(-0.04 * size)
                .foregroundStyle(Palette.tinta)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Klav")
    }
}

/// A small mark in cobalt before a line about an agent ("■ New agent").
struct AgentMark: View {
    let text: Text

    init(text: LocalizedStringKey) { self.text = Text(text) }

    var body: some View {
        HStack(spacing: 7) {
            Rectangle().fill(Palette.cobalto).frame(width: 7, height: 7)
            // The agent chose its name: two lines at most, whatever it is.
            text.font(.ui(13, .medium, relativeTo: .subheadline)).foregroundStyle(Palette.cobalto)
                .lineLimit(2)
                .truncationMode(.tail)
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Buttons

/// The primary action: a block of ink (paper in dark).
struct PrimaryButtonStyle: ButtonStyle {
    var compact = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ui(compact ? 14 : 16, .medium))
            .foregroundStyle(enabled ? Palette.botonTexto : Palette.gris)
            .padding(.horizontal, compact ? 14 : 18)
            .frame(maxWidth: compact ? nil : .infinity, minHeight: compact ? 36 : 52)
            // Disabled: mist with grey text, so it does not read as a block.
            .background(enabled ? Palette.boton.opacity(configuration.isPressed ? 0.82 : 1) : Palette.niebla)
            .overlay(Rectangle().strokeBorder(enabled ? Color.clear : Palette.linea, lineWidth: 1))
            .contentShape(Rectangle())
    }
}

/// A second action: ink on paper with a line around it. `danger` paints
/// the text red (deny, "They don’t match", the trash).
struct SecondaryButtonStyle: ButtonStyle {
    var compact = false
    var danger = false
    var block = true
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ui(compact ? 14 : 16, .medium))
            .foregroundStyle(danger ? Palette.rojo : Palette.tinta)
            .padding(.horizontal, compact ? 12 : 18)
            .frame(maxWidth: block && !compact ? .infinity : nil, minHeight: compact ? 36 : 52)
            .background(configuration.isPressed ? Palette.niebla : Palette.papel)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .opacity(enabled ? 1 : 0.5)
            .contentShape(Rectangle())
    }
}

/// The second way to do something: grey, underlined text.
struct LinkButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ui(15))
            .foregroundStyle(configuration.isPressed ? Palette.tinta : Palette.gris)
            .underline(true, color: configuration.isPressed ? Palette.tinta : Palette.linea)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
    }
}

/// 16×16 line icons, 1.5 pt strokes, square ends (the extension's `kit.ts`).
///
/// The kinds of items and the Mac's sidebar have their own, drawn on the
/// same grid (docs/diseno-visual §7): `Kind.icon` and `VaultFilter.icon`
/// pick them, and `kit.ts` has the same paths for the extension. A dot is
/// a stroke of almost no length, so the square cap draws it.
enum Icon {
    case copy, close, back, plus, check, search, gear, refresh
    /// All items: four squares.
    case grid
    /// A login: a field with a hidden value.
    case field
    /// One-time codes: a stopwatch.
    case timer
    case card
    /// A secure note: a page with lines.
    case page
    /// A file: a page with a folded corner.
    case file
    /// An API key: braces.
    case braces
    /// An SSH key: a shell prompt.
    case prompt
    /// An address: a house.
    case house
    /// A vault: a safe with its dial.
    case safe
    /// Agents' requests: a tray.
    case inbox
    case robot
    /// Vault health (the extension's `pulse`).
    case pulse
    /// The Mac's Activity: a log, one line per event.
    case list
    /// The Mac's Clients: a plug.
    case plug
    /// «Pause agents»: two bars.
    case pause
    /// The Mac's Sandboxes: a box seen from a corner.
    case cube

    func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height) / 16
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: rect.minX + x * s, y: rect.minY + y * s) }
        var path = Path()
        func line(_ points: CGPoint...) { path.addLines(points) }
        func box(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat) {
            path.addRect(CGRect(origin: p(x, y), size: CGSize(width: w * s, height: h * s)))
        }
        func shape(_ points: CGPoint...) { path.addLines(points); path.closeSubpath() }
        func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) {
            path.addEllipse(in: CGRect(origin: p(x - r, y - r), size: CGSize(width: 2 * r * s, height: 2 * r * s)))
        }
        func dot(_ x: CGFloat, _ y: CGFloat) { line(p(x, y), p(x + 0.01, y)) }
        switch self {
        case .grid:
            box(3.5, 3.5, 3.5, 3.5); box(9, 3.5, 3.5, 3.5)
            box(3.5, 9, 3.5, 3.5); box(9, 9, 3.5, 3.5)
        case .field:
            box(2.5, 5, 11, 6)
            dot(5.25, 8); dot(8, 8); dot(10.75, 8)
        case .timer:
            circle(8, 9, 4.5)
            line(p(8, 9), p(8, 6.75))
            line(p(6.25, 2.5), p(9.75, 2.5))
        case .card:
            box(2.5, 4, 11, 8)
            line(p(2.5, 7), p(13.5, 7))
            line(p(5, 9.75), p(7, 9.75))
        case .page:
            box(3.5, 2.5, 9, 11)
            line(p(6, 6), p(10, 6)); line(p(6, 8.5), p(10, 8.5)); line(p(6, 11), p(8, 11))
        case .file:
            shape(p(3.5, 2.5), p(9, 2.5), p(12.5, 6), p(12.5, 13.5), p(3.5, 13.5))
            line(p(9, 2.5), p(9, 6), p(12.5, 6))
        case .braces:
            line(p(5.5, 3), p(4.5, 3), p(4.5, 6.75), p(3, 8), p(4.5, 9.25), p(4.5, 13), p(5.5, 13))
            line(p(10.5, 3), p(11.5, 3), p(11.5, 6.75), p(13, 8), p(11.5, 9.25), p(11.5, 13), p(10.5, 13))
        case .prompt:
            line(p(3.5, 4.5), p(7, 8), p(3.5, 11.5))
            line(p(8.5, 12), p(12.5, 12))
        case .house:
            shape(p(3, 7.5), p(8, 3), p(13, 7.5), p(13, 13.5), p(3, 13.5))
        case .safe:
            box(2.5, 3, 11, 10)
            circle(8, 8, 2.5)
            line(p(10.5, 8), p(12, 8))
        case .inbox:
            line(p(2.5, 9), p(5.5, 9), p(6.25, 10.75), p(9.75, 10.75), p(10.5, 9), p(13.5, 9))
            shape(p(2.5, 9), p(2.5, 13), p(13.5, 13), p(13.5, 9), p(11.5, 3.5), p(4.5, 3.5))
        case .robot:
            box(3.5, 6, 9, 7)
            line(p(8, 3), p(8, 6))
            dot(6.25, 9.25); dot(9.75, 9.25)
        case .pulse:
            line(p(2, 8.5), p(5, 8.5), p(6.5, 5), p(9.5, 12), p(11, 8.5), p(14, 8.5))
        case .list:
            dot(3.5, 4.5); line(p(6, 4.5), p(13, 4.5))
            dot(3.5, 8); line(p(6, 8), p(13, 8))
            dot(3.5, 11.5); line(p(6, 11.5), p(10.5, 11.5))
        case .plug:
            line(p(6, 2.5), p(6, 5.5)); line(p(10, 2.5), p(10, 5.5))
            shape(p(4, 5.5), p(12, 5.5), p(12, 8), p(10, 10.5), p(6, 10.5), p(4, 8))
            line(p(8, 10.5), p(8, 13.5))
        case .pause:
            line(p(5.5, 3.5), p(5.5, 12.5)); line(p(10.5, 3.5), p(10.5, 12.5))
        case .cube:
            shape(p(8, 2.5), p(13, 5.25), p(13, 10.75), p(8, 13.5), p(3, 10.75), p(3, 5.25))
            line(p(3, 5.25), p(8, 8), p(13, 5.25))
            line(p(8, 8), p(8, 13.5))
        case .copy:
            path.addRect(CGRect(origin: p(5.5, 5.5), size: CGSize(width: 7 * s, height: 7 * s)))
            line(p(3.5, 10.5), p(3.5, 3.5), p(10.5, 3.5))
        case .close:
            line(p(4, 4), p(12, 12))
            line(p(12, 4), p(4, 12))
        case .back:
            line(p(10, 3.5), p(5.5, 8), p(10, 12.5))
        case .plus:
            line(p(8, 3.5), p(8, 12.5))
            line(p(3.5, 8), p(12.5, 8))
        case .check:
            line(p(3.5, 8.5), p(6.5, 11.5), p(12.5, 5))
        case .search:
            path.addEllipse(in: CGRect(origin: p(3.5, 3.5), size: CGSize(width: 7 * s, height: 7 * s)))
            line(p(9.5, 10), p(12.5, 13))
        case .refresh:
            path.addArc(center: p(8, 8), radius: 4.5 * s, startAngle: .degrees(-45), endAngle: .degrees(0), clockwise: true)
            line(p(12.5, 3), p(12.5, 5.5), p(10, 5.5))
        case .gear:
            path.addEllipse(in: CGRect(origin: p(5.75, 5.75), size: CGSize(width: 4.5 * s, height: 4.5 * s)))
            line(p(8, 2), p(8, 4)); line(p(8, 12), p(8, 14)); line(p(2, 8), p(4, 8)); line(p(12, 8), p(14, 8))
            line(p(3.8, 3.8), p(5.2, 5.2)); line(p(10.8, 10.8), p(12.2, 12.2))
            line(p(3.8, 12.2), p(5.2, 10.8)); line(p(10.8, 5.2), p(12.2, 3.8))
        }
        return path
    }
}

struct IconView: View {
    let icon: Icon
    var size: CGFloat = 16

    var body: some View {
        Canvas { context, canvasSize in
            context.stroke(icon.path(in: CGRect(origin: .zero, size: canvasSize)), with: .foreground,
                           style: StrokeStyle(lineWidth: 1.5 * canvasSize.width / 16, lineCap: .square))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// An action icon in a square with a line around it; the touch area is
/// 44 pt even when the square is smaller.
struct IconButton: View {
    let icon: Icon
    let label: Text
    var size: CGFloat = 36
    let action: () -> Void

    init(icon: Icon, label: LocalizedStringKey, size: CGFloat = 36, action: @escaping () -> Void) {
        self.icon = icon
        self.label = Text(label)
        self.size = size
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            IconView(icon: icon, size: 16)
        }
        .buttonStyle(IconButtonStyle(size: size))
        .accessibilityLabel(label)
    }
}

struct IconButtonStyle: ButtonStyle {
    var size: CGFloat = 36

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(configuration.isPressed ? Palette.tinta : Palette.gris)
            .frame(width: size, height: size)
            .background(configuration.isPressed ? Palette.niebla : Palette.papel)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .padding(max(0, (44 - size) / 2))
            .contentShape(Rectangle())
            .padding(-max(0, (44 - size) / 2))
    }
}

// MARK: - Blocks of the interface

/// 9 pt marks in "Cruz" at the four corners of a block that groups data
/// (an item's fields, an agent's request, the six words).
struct CrossCorners: ViewModifier {
    func body(content: Content) -> some View {
        content.overlay {
            GeometryReader { geo in
                Path { p in
                    let w = geo.size.width, h = geo.size.height
                    for (x, y) in [(0.0, 0.0), (w, 0), (0, h), (w, h)] {
                        p.move(to: CGPoint(x: x - 4.5, y: y)); p.addLine(to: CGPoint(x: x + 4.5, y: y))
                        p.move(to: CGPoint(x: x, y: y - 4.5)); p.addLine(to: CGPoint(x: x, y: y + 4.5))
                    }
                }
                .stroke(Palette.cruz, lineWidth: 1)
            }
            .allowsHitTesting(false)
            .accessibilityHidden(true)
        }
    }
}

extension View {
    func crossCorners() -> some View { modifier(CrossCorners()) }
}

/// A thin line between rows.
struct Rule: View {
    var body: some View { Rectangle().fill(Palette.linea).frame(height: 1) }
}

/// The name of a group, followed by a line ("Your vault ———"). A literal
/// is a key of the string catalog; a `String` is shown as is.
struct SectionLabel: View {
    let text: Text
    init(_ key: LocalizedStringKey) { self.text = Text(key) }
    @_disfavoredOverload
    init<S: StringProtocol>(_ string: S) { self.text = Text(string) }

    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        HStack(spacing: 10) {
            // One line, unless accessibility text would cut it short.
            text
                .font(.ui(13, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
                .lineLimit(typeSize.isAccessibilitySize ? nil : 1)
                .fixedSize(horizontal: false, vertical: typeSize.isAccessibilitySize)
                .layoutPriority(1)
            Rule()
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// The item's square: its site's logo in ink if Klav ships one
/// (`SiteIcons`), else its initial. `site` is the item's first URL; cards
/// and notes have none and keep their initial.
struct Tile: View {
    let title: String
    var site: String? = nil
    var size: CGFloat = 34

    var body: some View {
        Group {
            if let logo = SiteIcons.logo(forSite: site) {
                // 16 of the extension's 28-point square, the same share here.
                LogoShape(d: logo)
                    .fill(Palette.tinta)
                    .frame(width: size * 16 / 28, height: size * 16 / 28)
            } else {
                Text(initial)
                    .font(.ui(size * 14 / 34, .semibold))
                    .foregroundStyle(Palette.tinta)
            }
        }
        .frame(width: size, height: size)
        .background(Palette.papel)
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .accessibilityHidden(true)
    }

    private var initial: String {
        title.trimmingCharacters(in: .whitespaces).first.map { String($0).uppercased() } ?? "·"
    }
}

/// The one-time code's period as blocks, one per second: those left in
/// cobalt from the left, those spent in "Línea". No smooth transitions.
struct TimeBlocks: View {
    let remaining: Int
    var period: Int = 30
    var height: CGFloat = 4

    var body: some View {
        HStack(spacing: 1) {
            ForEach(0..<max(1, period), id: \.self) { i in
                Rectangle().fill(i < remaining ? Palette.cobalto : Palette.linea)
            }
        }
        .frame(height: height)
        .transaction { $0.animation = nil }
        .accessibilityHidden(true)
    }
}

/// Groups a one-time code as 289 591 (easier to read aloud).
func spacedCode(_ code: String) -> String {
    switch code.count {
    case 6: return "\(code.prefix(3)) \(code.suffix(3))"
    case 8: return "\(code.prefix(4)) \(code.suffix(4))"
    default: return code
    }
}

/// A notice: ink on mist with a line on the left, red for errors (the red
/// marks, the text stays ink so it reads well).
struct Notice: View {
    enum Tone { case error, info }
    let text: String
    var tone: Tone = .error

    var body: some View {
        HStack(spacing: 0) {
            Rectangle().fill(tone == .error ? Palette.rojo : Palette.tinta).frame(width: 2)
            Text(text)
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 10)
                .padding(.horizontal, 12)
        }
        .background(Palette.niebla)
        .accessibilityElement(children: .combine)
    }
}

/// The name above a field.
struct FieldLabel: View {
    let text: Text
    init(_ key: LocalizedStringKey) { self.text = Text(key) }
    @_disfavoredOverload
    init<S: StringProtocol>(_ string: S) { self.text = Text(string) }

    var body: some View {
        text
            .font(.ui(13, relativeTo: .subheadline))
            .foregroundStyle(Palette.gris)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A text input: a line around it, cobalt when focused.
struct InputBox: ViewModifier {
    var focused: Bool
    var font: Font = .ui(16)

    func body(content: Content) -> some View {
        content
            .font(font)
            .foregroundStyle(Palette.tinta)
            .tint(Palette.cobalto)
            .padding(.horizontal, 12)
            .frame(minHeight: 48)
            .background(Palette.papel)
            .overlay(Rectangle().strokeBorder(focused ? Palette.cobalto : Palette.linea, lineWidth: focused ? 1.5 : 1))
    }
}

extension View {
    func inputBox(focused: Bool, font: Font = .ui(16)) -> some View {
        modifier(InputBox(focused: focused, font: font))
    }
}

/// A field's placeholder, from the string catalog (an example address or
/// name, translated) or, for a `String`, verbatim.
func placeholder(_ key: LocalizedStringKey, font: Font = .ui(16)) -> Text {
    Text(key).font(font).foregroundColor(Palette.gris)
}

@_disfavoredOverload
func placeholder<S: StringProtocol>(_ text: S, font: Font = .ui(16)) -> Text {
    Text(verbatim: String(text)).font(font).foregroundColor(Palette.gris)
}

/// A square check box in ink, like the extension's settings (no pills).
struct SquareToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(alignment: .center, spacing: 12) {
                configuration.label
                    .frame(maxWidth: .infinity, alignment: .leading)
                ZStack {
                    Rectangle().fill(configuration.isOn ? Palette.boton : Palette.papel)
                    Rectangle().strokeBorder(Palette.tinta, lineWidth: 1)
                    if configuration.isOn {
                        IconView(icon: .check, size: 16).foregroundStyle(Palette.botonTexto)
                    }
                }
                .frame(width: 22, height: 22)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? Text("On") : Text("Off"))
        .accessibilityAddTraits(.isToggle)
    }
}

// MARK: - Toast

/// A short message at the bottom of the screen.
struct Toast: Equatable {
    let id = UUID()
    let text: String
    /// Seconds until the clipboard is cleared (the toast counts them down).
    var clears: TimeInterval?
}

/// Floats over the screen with an ink edge, as in the extension; after a
/// copy it counts down the seconds the value stays on the clipboard.
struct ToastView: View {
    let toast: Toast
    @State private var shown = Date()

    var body: some View {
        HStack(spacing: 10) {
            if toast.clears != nil {
                IconView(icon: .check, size: 16).foregroundStyle(Palette.tinta)
            }
            if let clears = toast.clears {
                TimelineView(.periodic(from: shown, by: 1)) { context in
                    let left = max(0, Int((clears - context.date.timeIntervalSince(shown)).rounded(.up)))
                    Text("Copied. Klav will clear it from the clipboard in \(left) s.")
                }
            } else {
                Text(toast.text)
            }
        }
        .font(.ui(14, relativeTo: .subheadline))
        .foregroundStyle(Palette.tinta)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Palette.papel)
        .overlay(Rectangle().strokeBorder(Palette.tinta, lineWidth: 1))
        .shadow(color: Color.black.opacity(0.22), radius: 16, y: 12)
        .padding(.horizontal, 16)
        .padding(.bottom, 12)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.updatesFrequently)
    }
}
