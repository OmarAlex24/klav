import SwiftUI

/// A dither field filling its frame with `pixel`-point dots (3 pt on iOS,
/// docs/diseno-visual §3). The image is drawn once per size and scheme and
/// kept in `Dither`'s cache; animated frames (`keep: false`) are not.
struct DitherView: View {
    let kind: Dither.Kind
    var palette: Dither.Palette = .blue
    var pixel: CGFloat = 3
    /// 0…1: pixels whose threshold is below it are transparent.
    var reveal: Double = 0
    /// Keep the image in the cache (false for animation frames).
    var keep = true

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        GeometryReader { geo in
            let width = max(1, Int((geo.size.width / pixel).rounded(.up)))
            let height = max(1, Int((geo.size.height / pixel).rounded(.up)))
            if let image = Dither.cachedImage(kind, palette: palette, dark: scheme == .dark,
                                              width: width, height: height, reveal: reveal, keep: keep) {
                Image(decorative: image, scale: 1)
                    .resizable()
                    .interpolation(.none)
                    .frame(width: CGFloat(width) * pixel, height: CGFloat(height) * pixel, alignment: .topLeading)
                    .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                    .clipped()
            }
        }
        .accessibilityHidden(true)
    }
}
