import SwiftUI

/// Klav's logo: a key on an 8×8 pixel grid, on its own, the same as the
/// browser extension (`shared/glyph.ts`).
enum KeyGlyph {
    /// The key, row by row: a ring on the left, the shaft and two teeth.
    static let rows: [String] = [
        "........",
        ".##.....",
        "#..#....",
        "#..#####",
        "#..#.#.#",
        ".##.....",
        "........",
        "........",
    ]

    /// The lit cells as (x, y).
    static let cells: [(x: Int, y: Int)] = rows.enumerated().flatMap { y, row in
        row.enumerated().compactMap { x, ch in ch == "#" ? (x, y) : nil }
    }
}

/// The key, cropped to its 8×5 cells (or the whole 8×8 grid with
/// `square`), drawn in whole cells.
struct KeyGlyphShape: Shape {
    var square = false

    func path(in rect: CGRect) -> Path {
        let top = square ? 0 : 1
        let rows = square ? 8 : 5
        let cell = min(rect.width / 8, rect.height / CGFloat(rows))
        let x0 = rect.minX + (rect.width - cell * 8) / 2
        let y0 = rect.minY + (rect.height - cell * CGFloat(rows)) / 2
        var path = Path()
        for (x, y) in KeyGlyph.cells {
            path.addRect(CGRect(x: x0 + CGFloat(x) * cell, y: y0 + CGFloat(y - top) * cell, width: cell, height: cell))
        }
        return path
    }
}
