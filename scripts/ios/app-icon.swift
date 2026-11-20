// Renders the app icon (Klav's pixel key over a field of dither) from the
// same code the app draws with. Run from the repo root:
//
//   scripts/ios/app-icon.sh
//
// It compiles this file with apps/ios/Shared/{Dither,Glyph}.swift for macOS
// and writes the light, dark and tinted 1024 × 1024 icons (iOS 18).
import AppKit
import CoreGraphics
import Foundation

@main
struct AppIcon {
    static let size = 1024
    /// One dither pixel; the key's cells are whole multiples of it.
    static let pixel = 16
    static let cell = 80

    struct Variant {
        let file: String
        /// Two colours for the field (dark → light), from `Dither.band()`.
        let field: [Dither.RGB]
        let key: Dither.RGB
    }

    static let variants = [
        // Navy and cobalt, the key in paper.
        Variant(file: "AppIcon.png", field: [Dither.RGB(0x0D1466), Dither.RGB(0x2337FF)], key: Dither.RGB(0xFFFFFF)),
        // Ink and the dark navy, the key in the dark dither's light tone.
        Variant(file: "AppIcon-dark.png", field: [Dither.RGB(0x09090B), Dither.RGB(0x0A0F4D)], key: Dither.RGB(0xC9CEFF)),
        // Grey levels only: iOS tints them.
        Variant(file: "AppIcon-tinted.png", field: [Dither.RGB(0x000000), Dither.RGB(0x2A2A2A)], key: Dither.RGB(0xFFFFFF)),
    ]

    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 2 else {
            FileHandle.standardError.write("usage: app-icon <AppIcon.appiconset>\n".data(using: .utf8)!)
            exit(2)
        }
        let dir = URL(fileURLWithPath: args[1])
        for variant in variants {
            try render(variant).write(to: dir.appendingPathComponent(variant.file))
        }
    }

    static func render(_ v: Variant) throws -> Data {
        let n = size / pixel
        let field = Dither.pixels(width: n, height: n, field: Dither.band(), palette: v.field)
        guard let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4,
                                  space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                  bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
        else { throw NSError(domain: "app-icon", code: 1) }
        // CoreGraphics' origin is bottom-left: flip so rows go down.
        ctx.translateBy(x: 0, y: CGFloat(size))
        ctx.scaleBy(x: 1, y: -1)
        func fill(_ c: Dither.RGB, _ rect: CGRect) {
            ctx.setFillColor(red: CGFloat(c.r) / 255, green: CGFloat(c.g) / 255, blue: CGFloat(c.b) / 255, alpha: 1)
            ctx.fill(rect)
        }
        for y in 0..<n {
            for x in 0..<n {
                let o = (y * n + x) * 4
                fill(Dither.RGB(UInt32(field[o]) << 16 | UInt32(field[o + 1]) << 8 | UInt32(field[o + 2])),
                     CGRect(x: x * pixel, y: y * pixel, width: pixel, height: pixel))
            }
        }
        // The key, cropped to its 8 × 5 cells, centred on the pixel grid.
        let x0 = (size - cell * 8) / 2
        let y0 = (size - cell * 5) / 2 / pixel * pixel
        for (x, y) in KeyGlyph.cells {
            fill(v.key, CGRect(x: x0 + x * cell, y: y0 + (y - 1) * cell, width: cell, height: cell))
        }
        guard let image = ctx.makeImage(),
              let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
        else { throw NSError(domain: "app-icon", code: 2) }
        return png
    }
}
