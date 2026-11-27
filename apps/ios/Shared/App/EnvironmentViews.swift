import SwiftUI

/// The padlock notice of a protected environment, or of an item one
/// protects (ADR 0032 §3.1), on the Mac and on the iPhone.
struct ProtectedNotice: View {
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            IconView(icon: .lock, size: 13)
                .foregroundStyle(Palette.tinta)
                .alignmentGuide(.firstTextBaseline) { $0[.bottom] - 2 }
            Text(verbatim: text)
                .font(.ui(13)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}
