import SwiftUI

/// «Who used it», in an item's detail (ADR 0033 §8.1): what the agents
/// did with this item, newest first, with how each use got through, and
/// «Open in the log». Only the agents' events: the person's own changes
/// are in Activity. Shown also when Development is hidden (E1).
struct WhoUsedIt: View {
    @EnvironmentObject private var model: MacModel
    let itemId: String
    @State private var uses: [ItemUseInfo] = []
    @State private var loaded = false

    /// The newest few: the rest are in Activity.
    static let shown = 5

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionLabel("Who used it").padding(.top, 28).padding(.bottom, 10)
            if loaded && uses.isEmpty {
                Text("No agent has used it.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
            } else if !uses.isEmpty {
                FieldBlock {
                    ForEach(Array(uses.prefix(Self.shown).enumerated()), id: \.element.entry.seq) { index, use in
                        if index > 0 { Rule() }
                        UseRow(use: use)
                    }
                }
                HStack(spacing: 10) {
                    if uses.count > Self.shown {
                        Text("\(Int64(uses.count - Self.shown)) more").font(.ui(12)).foregroundStyle(Palette.gris)
                    }
                    Spacer()
                    Button("Open in the log") { model.openActivity(item: itemId) }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                }
                .padding(.top, 10)
            }
        }
        .task(id: "\(itemId)|\(model.generation)") { await load() }
    }

    private func load() async {
        let id = itemId
        if let activity = try? await model.run({ try $0.itemActivity(item: id) }) {
            uses = activity.uses
        }
        loaded = true
    }
}

private struct UseRow: View {
    let use: ItemUseInfo

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                ActivityWords.sentence(use.entry, size: 13.5)
                    .fixedSize(horizontal: false, vertical: true)
                if let reason = use.entry.reason, !reason.isEmpty {
                    ReasonLine(reason: reason)
                }
                Text(verbatim: [ActivityWords.how(use), ActivityWords.when(use.entry.atMs)]
                    .filter { !$0.isEmpty }.joined(separator: " · "))
                    .font(.ui(12)).foregroundStyle(use.how == .denied ? Palette.rojo : Palette.gris)
            }
            Spacer(minLength: 10)
            HStack(spacing: 6) {
                ForEach(use.entry.alerts.filter { $0 != "denied" }, id: \.self) { alert in
                    Tag(text: ActivityWords.alert(alert), color: alert == "first_use" ? Palette.tinta : Palette.rojo)
                }
            }
            .fixedSize()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .accessibilityElement(children: .combine)
    }
}
