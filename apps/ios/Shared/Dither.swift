import CoreGraphics
import Foundation

/// Klav's ordered dither (docs/diseno-visual §3), a port of the browser
/// extension's `shared/dither.ts`: a field is a function
/// `(u, v, aspect) → brightness 0…1` spread over a palette of 2 or 3
/// colours with an 8×8 Bayer matrix. Locked or hidden things look like
/// pixel noise; when they open, the threshold rises and they dissolve.
///
/// CoreGraphics only (no UIKit or SwiftUI), so `scripts/ios/app-icon.swift`
/// can draw the icon with it on macOS.
enum Dither {
    /// The 8×8 Bayer matrix (each value 0…63 once).
    static let bayer: [[Int]] = [
        [0, 32, 8, 40, 2, 34, 10, 42],
        [48, 16, 56, 24, 50, 18, 58, 26],
        [12, 44, 4, 36, 14, 46, 6, 38],
        [60, 28, 52, 20, 62, 30, 54, 22],
        [3, 35, 11, 43, 1, 33, 9, 41],
        [51, 19, 59, 27, 49, 17, 57, 25],
        [15, 47, 7, 39, 13, 45, 5, 37],
        [63, 31, 55, 23, 61, 29, 53, 21],
    ]

    /// The threshold of pixel (x, y), in (0, 1).
    static func threshold(_ x: Int, _ y: Int) -> Double {
        (Double(bayer[y & 7][x & 7]) + 0.5) / 64
    }

    /// The palette index for brightness `b` (0…1) over `n` colours at
    /// threshold `th`.
    static func pick(_ b: Double, _ n: Int, _ th: Double) -> Int {
        let steps = n - 1
        let s = min(1, max(0, b)) * Double(steps)
        let i = min(steps - 1, Int(s.rounded(.down)))
        return s - Double(i) > th ? i + 1 : i
    }

    // MARK: Noise

    /// The extension's integer hash, with JavaScript's 32-bit wrapping.
    private static func hash(_ x: Int, _ y: Int, _ seed: Int) -> Double {
        let sum = Int64(x) * 374_761_393 + Int64(y) * 668_265_263 + Int64(seed) * 2_147_483_647
        var h = UInt32(truncatingIfNeeded: sum)
        h = (h ^ (h >> 13)) &* 1_274_126_177
        return Double(h ^ (h >> 16)) / 4_294_967_295
    }

    /// Smooth value noise in 0…1 (deterministic: the same picture every time).
    static func valueNoise(_ x: Double, _ y: Double, seed: Int = 7) -> Double {
        let xf = x.rounded(.down)
        let yf = y.rounded(.down)
        let xi = Int(xf)
        let yi = Int(yf)
        let fx = x - xf
        let fy = y - yf
        let sx = fx * fx * (3 - 2 * fx)
        let sy = fy * fy * (3 - 2 * fy)
        let a = hash(xi, yi, seed)
        let b = hash(xi + 1, yi, seed)
        let c = hash(xi, yi + 1, seed)
        let d = hash(xi + 1, yi + 1, seed)
        return a + (b - a) * sx + (c - a) * sy + (a - b - c + d) * sx * sy
    }

    /// Horizontal streaks: noise stretched along x.
    private static func streaks(_ u: Double, _ v: Double, _ aspect: Double, _ rows: Double) -> Double {
        valueNoise(u * aspect * 2.2, v * rows) * 0.65 + valueNoise(u * aspect * 9, v * rows * 2, seed: 11) * 0.35
    }

    private static func clamp(_ n: Double) -> Double { min(1, max(0, n)) }

    // MARK: Fields

    /// A brightness field over the unit square; `aspect` is width / height.
    typealias Field = (_ u: Double, _ v: Double, _ aspect: Double) -> Double

    /// Distance (in units of the field's height) from (x, y) to a keyhole
    /// centred at (cx, cy): a circle and a slot that widens downwards.
    /// Negative inside.
    static func keyholeDistance(_ x: Double, _ y: Double, _ cx: Double, _ cy: Double, _ r: Double) -> Double {
        let circle = hypot(x - cx, y - cy) - r
        let top = cy
        let bottom = cy + r * 2.6
        let t = clamp((y - top) / (bottom - top))
        let half = r * (0.42 + 0.36 * t)
        let dx = abs(x - cx) - half
        let dy = max(top - y, y - bottom)
        let slot = max(dx, dy)
        return min(circle, slot)
    }

    /// The lock screen: a keyhole of light with an exponential glow, over a
    /// navy ground that lightens downwards with horizontal streaks. `open`
    /// (0…1) floods the field with the keyhole's light (unlocking).
    static func keyhole(open: Double = 0) -> Field {
        { u, v, aspect in
            let x = u * aspect
            let cx = aspect / 2
            let d = keyholeDistance(x, v, cx, 0.36, 0.13)
            if d <= 0 { return 1 }
            let glow = exp(-d * 16) * 0.75
            let ground = 0.12 + v * 0.42 + (streaks(u, v, aspect, 34) - 0.5) * 0.5
            let sparks = v > 0.72 ? max(0, valueNoise(u * aspect * 5, v * 60, seed: 3) - 0.78) * 2.4 : 0
            let base = clamp(max(ground + sparks, glow + ground * 0.4))
            if open <= 0 { return base }
            let reach = open * 1.6 - d * 1.2
            return clamp(base + max(0, reach) + open * open * 0.9)
        }
    }

    /// Agents' requests and notices: a vertical gradient with streaks.
    static func band() -> Field {
        { u, v, aspect in clamp(0.08 + v * 0.95 + (streaks(u, v, aspect, 22) - 0.5) * 0.45) }
    }

    /// A hidden secret: two light greys of noise on paper (instead of ••••).
    static func mask() -> Field {
        { u, v, aspect in
            clamp(valueNoise(u * aspect * 6, v * 3, seed: 5) * 0.55 + valueNoise(u * aspect * 24, v * 9, seed: 9) * 0.45)
        }
    }

    // MARK: Pixels

    /// An opaque RGB colour, 0…255 per channel.
    struct RGB: Hashable {
        let r: UInt8, g: UInt8, b: UInt8

        init(_ hex: UInt32) {
            r = UInt8((hex >> 16) & 255)
            g = UInt8((hex >> 8) & 255)
            b = UInt8(hex & 255)
        }
    }

    /// The RGBA pixels of `field` at `width`×`height` dither pixels.
    /// `reveal` (0…1) makes pixels transparent once their threshold is below
    /// it: the mask dissolving into the text under it.
    static func pixels(width: Int, height: Int, field: Field, palette: [RGB], reveal: Double = 0) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: width * height * 4)
        let aspect = Double(width) / Double(max(1, height))
        for y in 0..<height {
            let v = height > 1 ? Double(y) / Double(height - 1) : 0
            for x in 0..<width {
                let th = threshold(x, y)
                if reveal > 0 && th < reveal { continue }
                let u = width > 1 ? Double(x) / Double(width - 1) : 0
                let colour = palette[pick(field(u, v, aspect), palette.count, th)]
                let o = (y * width + x) * 4
                out[o] = colour.r
                out[o + 1] = colour.g
                out[o + 2] = colour.b
                out[o + 3] = 255
            }
        }
        return out
    }

    /// The same pixels as a `CGImage`, one image pixel per dither pixel
    /// (scale it up with no interpolation). Transparent pixels are
    /// premultiplied, so the image composites as the canvas does.
    static func image(width: Int, height: Int, field: Field, palette: [RGB], reveal: Double = 0) -> CGImage? {
        guard width > 0, height > 0 else { return nil }
        let bytes = pixels(width: width, height: height, field: field, palette: palette, reveal: reveal)
        guard let provider = CGDataProvider(data: Data(bytes) as CFData) else { return nil }
        return CGImage(
            width: width, height: height,
            bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: width * 4,
            space: CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue),
            provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent
        )
    }
}

/// The palettes of the spec, light and dark.
extension Dither {
    enum Palette: String {
        /// Navy → cobalt → paper (dark: navy → cobalt → #C9CEFF).
        case blue
        /// A hidden secret: paper → two greys.
        case mask

        func colours(dark: Bool) -> [RGB] {
            switch (self, dark) {
            case (.blue, false): return [RGB(0x0D1466), RGB(0x2337FF), RGB(0xFFFFFF)]
            case (.blue, true): return [RGB(0x0A0F4D), RGB(0x4555FF), RGB(0xC9CEFF)]
            case (.mask, false): return [RGB(0xFFFFFF), RGB(0xE4E4E7), RGB(0xC8C8CE)]
            case (.mask, true): return [RGB(0x09090B), RGB(0x27272A), RGB(0x3F3F46)]
            }
        }
    }

    /// The fields the interface draws, by name (for the cache key).
    enum Kind: Hashable {
        case keyhole(open: Double)
        case band
        case mask

        var field: Field {
            switch self {
            case .keyhole(let open): return Dither.keyhole(open: open)
            case .band: return Dither.band()
            case .mask: return Dither.mask()
            }
        }
    }

    /// Images already drawn, by field, palette, scheme and size. A field is
    /// computed once per size and scheme; frames of an animation are not
    /// kept (they are drawn once).
    private final class Box { let image: CGImage; init(_ image: CGImage) { self.image = image } }
    private static let cache: NSCache<NSString, Box> = {
        let cache = NSCache<NSString, Box>()
        cache.countLimit = 24
        return cache
    }()
    private static let lock = NSLock()

    /// The image of `kind` at `width`×`height` dither pixels, from the cache
    /// when it was drawn before.
    static func cachedImage(_ kind: Kind, palette: Palette, dark: Bool, width: Int, height: Int,
                            reveal: Double = 0, keep: Bool = true) -> CGImage? {
        let id = "\(kind)|\(palette.rawValue)|\(dark)|\(width)x\(height)|\(reveal)" as NSString
        lock.lock()
        let hit = cache.object(forKey: id)?.image
        lock.unlock()
        if let hit { return hit }
        guard let image = image(width: width, height: height, field: kind.field,
                                palette: palette.colours(dark: dark), reveal: reveal) else { return nil }
        if keep {
            lock.lock()
            cache.setObject(Box(image), forKey: id)
            lock.unlock()
        }
        return image
    }
}
