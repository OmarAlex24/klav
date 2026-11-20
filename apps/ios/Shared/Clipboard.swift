#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif
import UniformTypeIdentifiers

/// Copies values out of the vault: this device only (no Handoff), and
/// gone from the clipboard after `clearAfter` seconds (T36).
enum Clipboard {
    static let clearAfter: TimeInterval = 30

    #if canImport(UIKit)
    static func copy(_ value: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(clearAfter),
            ]
        )
    }
    #else
    /// Clipboard managers that follow nspasteboard.org skip a copy marked
    /// concealed and transient.
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// macOS has no expiration date for the clipboard: Klav clears it
    /// itself after `clearAfter`, unless something else was copied since.
    static func copy(_ value: String) {
        let board = NSPasteboard.general
        board.prepareForNewContents(with: .currentHostOnly)
        board.setString(value, forType: .string)
        board.setString("", forType: concealed)
        board.setString("", forType: transient)
        let count = board.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if board.changeCount == count { board.clearContents() }
        }
    }
    #endif
}
