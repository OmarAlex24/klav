// Makes the Mac app's icon from the iPhone's (ADR 0027): the same pixel art
// in macOS's rounded square, with the system's margin, at every size.
//
//   swift scripts/macos/app-icon.swift
//
// The art is 32 cells of 32 px; at 832 px each cell is 26 px, so nothing
// gets resampled between pixels.
import AppKit

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
let source = root.appendingPathComponent("apps/ios/Klav/Assets.xcassets/AppIcon.appiconset/AppIcon.png")
let out = root.appendingPathComponent("apps/ios/Mac/Assets.xcassets/AppIcon.appiconset")
guard let art = NSImage(contentsOf: source)?.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    fatalError("cannot read \(source.path)")
}

func render(_ size: Int) -> Data {
    let scale = CGFloat(size) / 1024
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let rect = CGRect(x: 96, y: 96, width: 832, height: 832).applying(CGAffineTransform(scaleX: scale, y: scale))
    let shape = CGPath(roundedRect: rect, cornerWidth: 186 * scale, cornerHeight: 186 * scale, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 * scale), blur: 20 * scale,
                  color: NSColor.black.withAlphaComponent(0.3).cgColor)
    ctx.addPath(shape)
    ctx.setFillColor(NSColor(red: 0.05, green: 0.08, blue: 0.38, alpha: 1).cgColor)
    ctx.fillPath()
    ctx.restoreGState()
    ctx.addPath(shape)
    ctx.clip()
    ctx.interpolationQuality = size >= 512 ? .none : .high
    ctx.draw(art, in: rect)
    let image = ctx.makeImage()!
    return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])!
}

try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
var images: [[String: String]] = []
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = points * scale
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        try render(pixels).write(to: out.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(scale)x", "filename": name])
    }
}
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
    .write(to: out.appendingPathComponent("Contents.json"))
let catalog = out.deletingLastPathComponent().appendingPathComponent("Contents.json")
try #"{"info":{"author":"xcode","version":1}}"#.data(using: .utf8)!.write(to: catalog)
print("wrote \(out.path)")
