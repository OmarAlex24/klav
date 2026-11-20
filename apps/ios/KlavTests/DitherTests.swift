import UIKit
import XCTest
@testable import Klav

/// The dither must draw the same picture as the browser extension's
/// `shared/dither.ts`. The expected numbers come from running that file
/// with Node (see the PR that added this test).
final class DitherTests: XCTestCase {
    func testTheBayerMatrixUsesEachValueOnce() {
        XCTAssertEqual(Dither.bayer.flatMap { $0 }.sorted(), Array(0..<64))
        XCTAssertEqual(Dither.threshold(0, 0), 0.5 / 64)
        XCTAssertEqual(Dither.threshold(8, 8), Dither.threshold(0, 0))
    }

    func testPickMatchesTheExtension() {
        XCTAssertEqual(Dither.pick(0.3, 2, 0.5), 0)
        XCTAssertEqual(Dither.pick(0.7, 2, 0.5), 1)
        XCTAssertEqual(Dither.pick(0.5, 3, 0.01), 1)
        XCTAssertEqual(Dither.pick(1, 3, 0.99), 2)
        XCTAssertEqual(Dither.pick(0, 3, 0.01), 0)
        XCTAssertEqual(Dither.pick(0.75, 3, 0.4), 2)
        XCTAssertEqual(Dither.pick(0.75, 3, 0.6), 1)
    }

    func testNoiseAndFieldsMatchTheExtension() {
        let e = 1e-12
        XCTAssertEqual(Dither.valueNoise(3.3, 1.7), 0.4857896804466762, accuracy: e)
        XCTAssertEqual(Dither.valueNoise(10.25, 4.5, seed: 11), 0.4146526015048504, accuracy: e)
        XCTAssertEqual(Dither.valueNoise(57.9, 33.1, seed: 3), 0.498663262154082, accuracy: e)
        XCTAssertEqual(Dither.keyholeDistance(0.1, 0.2, 0.5, 0.36, 0.13), 0.30081318457076034, accuracy: e)

        let expected: [(u: Double, v: Double, a: Double, keyhole: Double, open: Double, band: Double, mask: Double)] = [
            (0.3, 0.6, 1.2, 0.31064208234577156, 0.9120390054226949, 0.6381485698980358, 0.2525859548714749),
            (0.02, 0.9, 0.75, 0.6232548835665843, 1, 0.9130967712815086, 0.5248127852340487),
            (0.77, 0.15, 0.75, 0.1365665748875933, 0.7264908687896123, 0.142343261913392, 0.42924878630113444),
            (0.5, 0.8, 2.5, 0.36337204921687394, 1, 0.7881679766023918, 0.4329801414103668),
        ]
        for p in expected {
            XCTAssertEqual(Dither.keyhole()(p.u, p.v, p.a), p.keyhole, accuracy: e)
            XCTAssertEqual(Dither.keyhole(open: 0.4)(p.u, p.v, p.a), p.open, accuracy: e)
            XCTAssertEqual(Dither.band()(p.u, p.v, p.a), p.band, accuracy: e)
            XCTAssertEqual(Dither.mask()(p.u, p.v, p.a), p.mask, accuracy: e)
        }
    }

    func testPixelsMatchTheExtension() {
        let palette = Dither.Palette.blue.colours(dark: false)
        let expected: [(String, Dither.Field, [Int], Int)] = [
            ("keyhole", Dither.keyhole(), [383, 681, 136], 302_166_517),
            ("band", Dither.band(), [232, 611, 357], 456_893_733),
            ("mask", Dither.mask(), [187, 889, 124], 834_577_735),
        ]
        for (name, field, counts, hash) in expected {
            let px = Dither.pixels(width: 40, height: 30, field: field, palette: palette)
            var seen = [0, 0, 0]
            var sum = 0
            for i in stride(from: 0, to: px.count, by: 4) {
                let index = palette.firstIndex { $0.r == px[i] && $0.g == px[i + 1] && $0.b == px[i + 2] } ?? -1
                seen[index] += 1
                sum = (sum * 31 + index) % 1_000_000_007
            }
            XCTAssertEqual(seen, counts, name)
            XCTAssertEqual(sum, hash, name)
        }
    }

    func testBrightnessMixesInProportion() {
        let px = Dither.pixels(width: 64, height: 64, field: { _, _, _ in 0.25 },
                               palette: [Dither.RGB(0x000000), Dither.RGB(0xFFFFFF)])
        let white = stride(from: 0, to: px.count, by: 4).filter { px[$0] == 255 }.count
        XCTAssertEqual(Double(white) / 4096, 0.25, accuracy: 0.005)
    }

    func testRevealLeavesPixelsTransparent() {
        let half = Dither.pixels(width: 8, height: 8, field: { _, _, _ in 1 },
                                 palette: [Dither.RGB(0x000000), Dither.RGB(0xFFFFFF)], reveal: 0.5)
        XCTAssertEqual(stride(from: 3, to: half.count, by: 4).filter { half[$0] == 0 }.count, 32)
    }

    func testTheKeyholeFloodsWhenItOpens() {
        let f = Dither.keyhole(open: 1)
        XCTAssertEqual(f(0.02, 0.02, 1.2), 1)
        XCTAssertEqual(f(0.98, 0.98, 1.2), 1)
        XCTAssertEqual(Dither.keyhole()(0.5, 0.36, 1.2), 1)
        XCTAssertLessThan(Dither.keyhole()(0.02, 0.02, 1.2), 0.45)
    }

    func testImagesAreCachedBySizeAndScheme() throws {
        let a = try XCTUnwrap(Dither.cachedImage(.band, palette: .blue, dark: false, width: 20, height: 40))
        let b = try XCTUnwrap(Dither.cachedImage(.band, palette: .blue, dark: false, width: 20, height: 40))
        XCTAssertTrue(a === b)
        let dark = try XCTUnwrap(Dither.cachedImage(.band, palette: .blue, dark: true, width: 20, height: 40))
        XCTAssertFalse(a === dark)
        XCTAssertEqual(a.width, 20)
        XCTAssertEqual(a.height, 40)
    }

    func testTheKeyGlyphIsTheExtensionsKey() {
        XCTAssertEqual(KeyGlyph.rows.count, 8)
        XCTAssertTrue(KeyGlyph.rows.allSatisfy { $0.count == 8 })
        XCTAssertEqual(KeyGlyph.cells.count, 16)
    }

    func testTheFontsAreRegistered() {
        for name in ["Geist-Regular", "Geist-Medium", "Geist-SemiBold", "GeistMono-Regular", "DepartureMono-Regular"] {
            XCTAssertNotNil(UIFont(name: name, size: 15), name)
        }
        XCTAssertEqual(spacedCode("289591"), "289 591")
        XCTAssertEqual(spacedCode("12345678"), "1234 5678")
    }
}
