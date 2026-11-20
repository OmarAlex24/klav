import SwiftUI

/// The password generator (ADR 0022 §1–§2) from the item editor, as on the
/// iPhone: four types, the password coloured by character class, its
/// strength in four segments, the site's rules, and every password kept in
/// the generator history (`klavd`'s outbox) before it is used or copied.
struct GeneratorSheet: View {
    /// The site it is for (the login's URL), for `smart`.
    let site: String?
    /// «Use this password»: the editor takes it.
    let onUse: (String) -> Void

    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    @AppStorage("generatorDefaultKind") private var defaultKind = "smart"

    @State private var kind: GeneratorType = .smart
    @State private var length = 20
    @State private var digits = true
    @State private var symbols = true
    @State private var words = 5
    @State private var pinLength = 6
    @State private var generated: GeneratedPassword?
    @State private var problem: String?
    @State private var started = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Title("Password generator", size: 20)
                Spacer()
            }
            .padding(.horizontal, 24)
            .frame(height: 56)
            .overlay(alignment: .bottom) { Rule() }

            VStack(alignment: .leading, spacing: 14) {
                kinds
                valueRow
                if let generated { strength(generated) }
                if let note = generated.flatMap({ GeneratorWords.rulesNote($0, kind: kind, site: site) }) {
                    Text(note).font(.ui(12.5)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                options
                Toggle(isOn: Binding(get: { defaultKind == kind.key }, set: { defaultKind = $0 ? kind.key : "smart" })) {
                    Text("Use as default for suggestions").font(.ui(14)).foregroundStyle(Palette.tinta)
                }
                .toggleStyle(SquareToggleStyle())
                if let problem { Notice(text: problem) }
            }
            .padding(24)

            HStack(spacing: 8) {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button("Use this password") { use() }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .keyboardShortcut(.defaultAction)
                    .disabled(generated == nil)
            }
            .padding(.horizontal, 24)
            .frame(height: 60)
            .overlay(alignment: .top) { Rule() }
        }
        .frame(width: 480)
        .background(Palette.papel)
        .task {
            guard !started else { return }
            started = true
            kind = GeneratorType(key: defaultKind) ?? .smart
            regenerate()
        }
        .onDisappear { generated = nil }
    }

    // MARK: Parts

    private var kinds: some View {
        HStack(spacing: 0) {
            ForEach(GeneratorType.all, id: \.key) { k in
                let on = k == kind
                Button {
                    kind = k
                    regenerate()
                } label: {
                    Text(k.name)
                        .font(.ui(13, .medium))
                        .foregroundStyle(on ? Palette.tinta : Palette.gris)
                        .frame(maxWidth: .infinity, minHeight: 34)
                        .background(on ? Palette.niebla : Palette.papel)
                        .overlay(alignment: .bottom) {
                            if on { Rectangle().fill(Palette.tinta).frame(height: 2) }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? [.isSelected] : [])
                if k != GeneratorType.all.last {
                    Rectangle().fill(Palette.linea).frame(width: 1, height: 34)
                }
            }
        }
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Password type")
    }

    private var valueRow: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(colored(generated?.value ?? " "))
                .font(.mono(15))
                .tracking(0.4)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, minHeight: 22, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(Palette.papel)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .crossCorners()
                .textSelection(.enabled)
                .accessibilityLabel("Generated password")
            IconButton(icon: .copy, label: "Copy the generated password", size: 40) { copy() }
                .help("Copy")
            IconButton(icon: .refresh, label: "Generate another", size: 40) { regenerate() }
                .help("Generate another")
        }
    }

    private func strength(_ g: GeneratedPassword) -> some View {
        let steps = ["weak": 1, "fair": 2, "strong": 3, "very_strong": 4][g.strength] ?? 1
        return HStack(spacing: 10) {
            HStack(spacing: 2) {
                ForEach(1...4, id: \.self) { i in
                    Rectangle()
                        .fill(i <= steps ? (g.strength == "weak" ? Palette.rojo : Palette.tinta) : Palette.linea)
                        .frame(width: 16, height: 6)
                }
            }
            .accessibilityHidden(true)
            Text("\(strengthName(g.strength)) · \(Int(g.bits.rounded())) bits")
                .font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
        }
    }

    @ViewBuilder
    private var options: some View {
        switch kind {
        case .random:
            VStack(alignment: .leading, spacing: 8) {
                step("Length", value: $length, range: 8...64)
                Toggle(isOn: $digits.onChange(regenerate)) { Text("Digits").font(.ui(14)) }.toggleStyle(SquareToggleStyle())
                Toggle(isOn: $symbols.onChange(regenerate)) { Text("Symbols").font(.ui(14)) }.toggleStyle(SquareToggleStyle())
            }
        case .memorable:
            step("Words", value: $words, range: 3...10)
        case .pin:
            step("Digits", value: $pinLength, range: 4...12)
        case .smart:
            EmptyView()
        }
    }

    private func step(_ label: LocalizedStringKey, value: Binding<Int>, range: ClosedRange<Int>) -> some View {
        HStack(spacing: 10) {
            Text(label).font(.ui(14)).foregroundStyle(Palette.gris)
            Spacer()
            Button("−") { value.wrappedValue -= 1; regenerate() }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                .disabled(value.wrappedValue <= range.lowerBound)
                .accessibilityLabel(Text("\(Text(label)): fewer"))
            Text(verbatim: "\(value.wrappedValue)")
                .font(.mono(14)).foregroundStyle(Palette.tinta)
                .frame(minWidth: 28)
            Button("+") { value.wrappedValue += 1; regenerate() }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                .disabled(value.wrappedValue >= range.upperBound)
                .accessibilityLabel(Text("\(Text(label)): more"))
        }
    }

    // MARK: Actions

    private func regenerate() {
        let input = GeneratorInput(kind: kind, length: UInt32(length), digits: digits, symbols: symbols,
                                   words: UInt32(words), pinLength: UInt32(pinLength))
        do {
            generated = try generate(input: input, host: site)
            problem = nil
        } catch {
            problem = describe(error)
        }
    }

    /// Keeps it in the generator history; `nil` when that worked.
    private func keep(_ value: String) async -> String? {
        let host = site
        do {
            _ = try await model.run { try $0.recordGenerated(value: value, host: host) }
            return nil
        } catch {
            return describe(error)
        }
    }

    private func copy() {
        guard let value = generated?.value else { return }
        Task {
            if let why = await keep(value) { problem = String(localized: "Klav couldn’t keep it in the generator history: \(why)") }
            model.copy(value)
        }
    }

    private func use() {
        guard let value = generated?.value else { return }
        Task {
            if let why = await keep(value) {
                problem = String(localized: "Klav couldn’t keep it in the generator history: \(why)")
                return
            }
            onUse(value)
            dismiss()
        }
    }
}
