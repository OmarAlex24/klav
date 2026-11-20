import SwiftUI

/// The password generator (ADR 0022 §1–§2), as in the browser extension:
/// four types, the password coloured by character class (letters in ink,
/// digits in grey, each symbol on a mist cell; no blue), its strength in
/// four segments, and every password kept in the generator history before
/// it is used or copied.
struct GeneratorSheet: View {
    /// The site it is for (the login's first URL), for `smart`.
    let site: String?
    /// «Use this password»: the editor takes it. `nil` outside the editor.
    var onUse: ((String) -> Void)? = nil

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var typeSize
    @AppStorage("generatorDefaultKind") private var defaultKind = "smart"

    @State private var kind: GeneratorType = .smart
    @State private var length = 20
    @State private var digits = true
    @State private var symbols = true
    @State private var words = 5
    @State private var pinLength = 6
    @State private var generated: GeneratedPassword?
    @State private var problem: String?
    @State private var showHistory = false
    @State private var started = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    Title("Password generator", size: 22)
                    Spacer()
                    Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
                }
                .padding(.horizontal, 20)
                .frame(minHeight: 64)
                .overlay(alignment: .bottom) { Rule() }
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        kinds
                        valueRow
                        if let generated { strength(generated) }
                        if let note = generated.flatMap({ GeneratorWords.rulesNote($0, kind: kind, site: site) }) {
                            Text(note)
                                .font(.ui(13, relativeTo: .footnote))
                                .foregroundStyle(Palette.gris)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        options
                        if let problem { Notice(text: problem) }
                        if onUse != nil {
                            Button("Use this password") { use() }
                                .buttonStyle(PrimaryButtonStyle())
                                .disabled(generated == nil)
                        }
                        Toggle(isOn: Binding(get: { defaultKind == kind.key }, set: { defaultKind = $0 ? kind.key : "smart" })) {
                            Text("Use as default for suggestions").font(.ui(15)).foregroundStyle(Palette.tinta)
                        }
                        .toggleStyle(SquareToggleStyle())
                        Button("Generator history") { showHistory = true }
                            .buttonStyle(LinkButtonStyle())
                    }
                    .padding(20)
                }
            }
            .background(Palette.papel)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(isPresented: $showHistory) {
                GeneratorHistoryView().environmentObject(model)
            }
        }
        // The app's toast sits under the sheet: show «Copied» here too.
        .toastHost(model)
        .task {
            guard !started else { return }
            started = true
            kind = GeneratorType(key: defaultKind) ?? .smart
            regenerate()
        }
    }

    // MARK: Parts

    /// With accessibility text the four types go one per row, so no name
    /// breaks mid-word; the chosen one keeps its ink rule, on the left.
    private var kinds: some View {
        let stacked = typeSize.isAccessibilitySize
        let layout = stacked ? AnyLayout(VStackLayout(spacing: 0)) : AnyLayout(HStackLayout(spacing: 0))
        return layout {
            ForEach(GeneratorType.all, id: \.key) { k in
                let on = k == kind
                Button {
                    kind = k
                    regenerate()
                } label: {
                    Text(k.name)
                        .font(.ui(14, .medium))
                        .foregroundStyle(on ? Palette.tinta : Palette.gris)
                        .padding(.horizontal, stacked ? 14 : 0)
                        .padding(.vertical, stacked ? 8 : 0)
                        .frame(maxWidth: .infinity, minHeight: 40, alignment: stacked ? .leading : .center)
                        .background(on ? Palette.niebla : Palette.papel)
                        .overlay(alignment: stacked ? .leading : .bottom) {
                            if on {
                                Rectangle().fill(Palette.tinta)
                                    .frame(width: stacked ? 2 : nil, height: stacked ? nil : 2)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? [.isSelected] : [])
                if k != GeneratorType.all.last {
                    Rectangle().fill(Palette.linea)
                        .frame(width: stacked ? nil : 1, height: stacked ? 1 : 40)
                }
            }
        }
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Password type")
    }

    /// With accessibility text, «Copy» and «Generate another» go under the
    /// password so it keeps the whole width.
    private var valueRow: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(alignment: .top, spacing: 8))
        return layout {
            Text(colored(generated?.value ?? " "))
                .font(.mono(17, relativeTo: .body))
                .tracking(0.4)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 11)
                .background(Palette.papel)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .textSelection(.enabled)
                .accessibilityLabel("Generated password")
            HStack(spacing: 8) {
                IconButton(icon: .copy, label: "Copy the generated password", size: 44) { copy() }
                IconButton(icon: .refresh, label: "Generate another", size: 44) { regenerate() }
            }
        }
    }

    private func strength(_ g: GeneratedPassword) -> some View {
        let steps = ["weak": 1, "fair": 2, "strong": 3, "very_strong": 4][g.strength] ?? 1
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(spacing: 10))
        return layout {
            HStack(spacing: 2) {
                ForEach(1...4, id: \.self) { i in
                    Rectangle()
                        .fill(i <= steps ? (g.strength == "weak" ? Palette.rojo : Palette.tinta) : Palette.linea)
                        .frame(width: 16, height: 6)
                }
            }
            .fixedSize()
            .accessibilityHidden(true)
            Text("\(strengthName(g.strength)) · \(Int(g.bits.rounded())) bits")
                .font(.ui(14, .medium))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var options: some View {
        switch kind {
        case .random:
            VStack(alignment: .leading, spacing: 10) {
                step("Length", value: $length, range: 8...64)
                Toggle(isOn: $digits.onChange(regenerate)) { Text("Digits").font(.ui(15)) }.toggleStyle(SquareToggleStyle())
                Toggle(isOn: $symbols.onChange(regenerate)) { Text("Symbols").font(.ui(15)) }.toggleStyle(SquareToggleStyle())
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
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(spacing: 10))
        return layout {
            Text(label).font(.ui(15)).foregroundStyle(Palette.gris)
            if !typeSize.isAccessibilitySize { Spacer() }
            stepper(label, value: value, range: range)
        }
    }

    private func stepper(_ label: LocalizedStringKey, value: Binding<Int>, range: ClosedRange<Int>) -> some View {
        HStack(spacing: 10) {
            Button("−") { value.wrappedValue -= 1; regenerate() }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .disabled(value.wrappedValue <= range.lowerBound)
                .accessibilityLabel(Text("\(Text(label)): fewer"))
            Text(verbatim: "\(value.wrappedValue)")
                .font(.mono(15, relativeTo: .body))
                .foregroundStyle(Palette.tinta)
                .frame(minWidth: 28)
            Button("+") { value.wrappedValue += 1; regenerate() }
                .buttonStyle(SecondaryButtonStyle(compact: true))
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
        guard let service = model.service else { return String(localized: "Klav is locked.") }
        let host = site
        do {
            try await service.run { core, _ in _ = try core.recordGenerated(value: value, host: host) }
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
        guard let value = generated?.value, let onUse else { return }
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

/// The generator history: newest first, a value only on «Copy». On a
/// deleted account's copy it only reads: copying works, deleting doesn't
/// (ADR 0037 §3, Q2 of the re-review).
struct GeneratorHistoryView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    /// Where the back button goes.
    var back: LocalizedStringKey = "Password generator"
    @State private var entries: [GeneratedEntryInfo]?
    @State private var problem: String?
    @State private var confirmClear = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button {
                    dismiss()
                } label: {
                    HStack(spacing: 4) {
                        IconView(icon: .back)
                        Text(back).font(.ui(15))
                    }
                    .foregroundStyle(Palette.gris)
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                Spacer()
            }
            .padding(.horizontal, 20)
            .frame(minHeight: 56)
            .overlay(alignment: .bottom) { Rule() }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Title("Generator history", size: 28).padding(.bottom, 6)
                    Text("Every password Klav generated, for a year")
                        .font(.ui(14, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .padding(.bottom, 18)
                    if let problem { Notice(text: problem).padding(.bottom, 12) }
                    if let entries {
                        if entries.isEmpty {
                            Text("Klav hasn’t generated any password yet.")
                                .font(.ui(15))
                                .foregroundStyle(Palette.gris)
                        } else {
                            FieldBlock {
                                ForEach(Array(entries.enumerated()), id: \.element.createdAt) { index, entry in
                                    if index > 0 { Rule() }
                                    row(entry, position: index + 1, count: entries.count)
                                }
                            }
                            if !model.readOnly {
                                Button("Delete history") { confirmClear = true }
                                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                                    .padding(.top, 20)
                            }
                        }
                    }
                }
                .padding(20)
            }
        }
        .background(Palette.papel)
        .toolbar(.hidden, for: .navigationBar)
        .task { await load() }
        .confirmationDialog(Text("Delete the generator history?"), isPresented: $confirmClear, titleVisibility: .visible) {
            Button("Delete history", role: .destructive) { clear() }
        } message: {
            Text("The passwords go from all your devices.")
        }
    }

    private func row(_ entry: GeneratedEntryInfo, position: Int, count: Int) -> some View {
        let when = Date(timeIntervalSince1970: TimeInterval(entry.createdAt) / 1000).formatted(date: .abbreviated, time: .shortened)
        var sub = [when]
        if let title = entry.savedInTitle { sub.append(String(localized: "Saved in \(title)")) }
        if entry.pending { sub.append(String(localized: "Not synced yet")) }
        // Its place in the list too: two generated in the same minute
        // would read the same.
        let place = Int64(position), total = Int64(count)
        return DetailRow {
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.host ?? String(localized: "No site"))
                    .font(.ui(16, .medium))
                    .foregroundStyle(Palette.tinta)
                Text(sub.joined(separator: " · "))
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
            }
        } actions: {
            IconButton(icon: .copy, label: "Copy the password generated \(when), \(place) of \(total)") { copy(entry) }
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        do {
            entries = try await service.run { core, _ in try core.generatorHistory() }
        } catch {
            problem = describe(error)
        }
    }

    private func copy(_ entry: GeneratedEntryInfo) {
        guard let service = model.service else { return }
        let at = entry.createdAt
        Task {
            do {
                let value = try await service.run { core, _ in try core.generatedValue(createdAt: at) }
                model.copy(value)
            } catch {
                problem = describe(error)
            }
        }
    }

    private func clear() {
        guard let service = model.service else { return }
        Task {
            do {
                try await service.run { core, _ in _ = try core.clearGeneratorHistory() }
                entries = []
            } catch {
                problem = describe(error)
            }
        }
    }
}
