import CoreImage
import CoreImage.CIFilterBuiltins
import UIKit
import XCTest
@testable import Klav

/// The import wizard's pieces that need no server (ADR 0024): reading QR
/// codes from a picture, the import session, the sources and their
/// Spanish. Previews and imports against a server are in
/// `crates/klav-ffi/tests/import.rs`. Only synthetic data.
final class ImportTests: XCTestCase {
    /// Google Authenticator's two QR codes of `examples/import/` (synthetic
    /// accounts, `JBSWY3DP…` secrets).
    private let links = [
        "otpauth-migration://offline?data=CjoKEnNhbXBsZS1naXRodWItb3RwIRIWR2l0SHViOmFuYUBleGFtcGxlLmNvbRoGR2l0SHViIAEoATACCjQKEnNhbXBsZS1kaXNjb3JkLW90cBIPYW5hQGV4YW1wbGUuY29tGgdEaXNjb3JkIAEoATACEAEYAiAAKLLyGQ%3D%3D",
        "otpauth-migration://offline?data=Ci8KE3NhbXBsZS1ob3RwLWNvdW50ZXISBmxlZ2FjeRoKTGVnYWN5IFZQTiABKAEwARABGAIgASiy8hk%3D",
    ]

    private let bitwarden = """
    {"encrypted": false, "folders": [], "items": [
      {"id": "1", "type": 1, "name": "GitHub", "favorite": false,
       "login": {"username": "ana@example.com", "password": "sample-1",
                 "uris": [{"uri": "https://github.com/login"}], "totp": null}},
      {"id": "2", "type": 1, "name": "Old forum", "deletedDate": "2026-01-01T00:00:00.000Z",
       "login": {"username": "ana", "password": "sample-2"}}
    ]}
    """

    private func qrPicture(_ text: String) throws -> Data {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        let image = try XCTUnwrap(filter.outputImage).transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let context = CIContext()
        let cg = try XCTUnwrap(context.createCGImage(image, from: image.extent))
        // A screenshot: the code on white, with a margin.
        let size = CGSize(width: image.extent.width + 160, height: image.extent.height + 320)
        let png = UIGraphicsImageRenderer(size: size).pngData { ctx in
            UIColor.white.setFill()
            ctx.fill(CGRect(origin: .zero, size: size))
            UIImage(cgImage: cg).draw(at: CGPoint(x: 80, y: 160))
        }
        return png
    }

    func testAScreenshotOfAQRCodeIsReadOnTheDevice() throws {
        let messages = QRReader.messages(in: try qrPicture(links[0]))
        XCTAssertEqual(messages, [links[0]])
        XCTAssertEqual(QRReader.messages(in: Data("not a picture".utf8)), [])
    }

    func testAnImportSessionReadsFilesAndQRCodes() throws {
        // Reading needs no account: nothing leaves the session until "Import".
        let session = ImportSession()
        try session.add(name: "bitwarden.json", data: Data(bitwarden.utf8), from: "bitwarden")
        var state = session.state()
        XCTAssertEqual(state.entries, 1)
        XCTAssertEqual(state.files.first?.format, "Bitwarden")
        XCTAssertEqual(state.files.first?.skipped.first?.at, "item 2")

        // The first QR code of two says the second is missing.
        let google = ImportSession()
        try google.add(name: "QR code 1", data: Data(links[0].utf8), from: "google")
        state = google.state()
        XCTAssertEqual(state.missing.first?.size, 2)
        XCTAssertEqual(state.missing.first?.missing, [2])
        XCTAssertEqual(missingText(state.missing[0]), "This export has 2 QR codes and 1 aren’t here yet. Add them too.")
        try google.add(name: "QR code 2", data: Data(links[1].utf8), from: "google")
        state = google.state()
        XCTAssertTrue(state.missing.isEmpty)
        // GitHub and Discord; the counter-based code (Legacy VPN) is skipped.
        XCTAssertEqual(state.entries, 2)
        XCTAssertTrue(state.files[1].skipped.contains { $0.reason.contains("HOTP") })
    }

    func testAFileFromTheWrongSourceIsRefusedWithItsName() {
        let session = ImportSession()
        XCTAssertThrowsError(try session.add(name: "bitwarden.json", data: Data(bitwarden.utf8), from: "firefox")) { error in
            guard case KlavError.Invalid(let message) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(message.hasPrefix("bitwarden.json: "), message)
            XCTAssertFalse(message.contains("sample-"), message)
        }
        XCTAssertEqual(session.state().entries, 0)
    }

    func testEverySourceSaysHowToExport() {
        for source in ImportSource.allCases {
            XCTAssertGreaterThanOrEqual(source.steps.count, 2, source.name)
            XCTAssertFalse(source.subtitle.isEmpty)
        }
        XCTAssertNil(ImportSource.authy.wire)
        XCTAssertEqual(ImportSource.onePassword.wire, "1password")
        XCTAssertEqual(importChange("password_replaced"), "new password, the old one goes to its history")
    }

    /// `key` from the string catalog in Spanish (the tests run in English).
    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    func testTheWizardSpeaksSpanish() {
        XCTAssertEqual(spanish("Where are you coming from?"), "¿De dónde vienes?")
        XCTAssertEqual(spanish("Now delete the export"), "Ahora borra la exportación")
        XCTAssertEqual(spanish("new password, the old one goes to its history"),
                       "contraseña nueva, la anterior pasa a su historial")
        XCTAssertEqual(spanish("Import from another app"), "Importar desde otra app")
        let plural = String.localizedStringWithFormat(spanish("%lld new items"), 1)
        XCTAssertEqual(plural, "1 elemento nuevo")
        let camera = Bundle.main.path(forResource: "es", ofType: "lproj")
            .flatMap(Bundle.init(path:))?
            .localizedString(forKey: "NSCameraUsageDescription", value: "MISSING", table: "InfoPlist")
        XCTAssertEqual(camera, "Klav usa la cámara solo para leer los QR de Google Authenticator cuando los importas.")
    }
}
