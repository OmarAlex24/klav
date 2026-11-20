import AppKit
import SwiftUI

/// «Uninstall Klav from this Mac» (ADR 0027 §4.1): says what goes and what
/// stays, then takes off the background service, the browsers' files and
/// the `klav` link. The vault on this Mac (`KLAV_HOME`) goes only if the
/// person ticks it; the account and the other devices stay as they are.
struct UninstallSheet: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.dismiss) private var dismiss
    @State private var deleteHome = false
    @State private var finished = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if finished {
                Title("Klav is off this Mac", size: 22)
                Text("Drag Klav from Applications to the Trash to finish. The extension stays in your browsers until you remove it there.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Show Klav in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    Button("Quit Klav") { NSApp.terminate(nil) }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                        .fixedSize()
                        .keyboardShortcut(.defaultAction)
                }
            } else {
                Title("Uninstall Klav from this Mac", size: 22)
                VStack(alignment: .leading, spacing: 6) {
                    FieldLabel("Klav takes off")
                    Line("The background service and its Login Items entry")
                    if installer.openAtLogin != .notRegistered, installer.openAtLogin != .notFound {
                        Line("Opening Klav at login")
                    }
                    Line("The file in each browser that lets the extension reach Klav")
                    if installer.link == .ours {
                        Line(String(localized: "The klav command (\(installer.paths.link.path)); macOS asks for the password"))
                    }
                }
                VStack(alignment: .leading, spacing: 6) {
                    FieldLabel("It stays")
                    Line("Your account, its vaults and your other devices")
                    Line("Another install’s files: those are not Klav.app’s")
                }
                Toggle(isOn: $deleteHome) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Also delete this Mac’s copy of the vault").font(.ui(13.5)).foregroundStyle(Palette.tinta)
                        Text(verbatim: installer.paths.klavHome.path)
                            .font(.mono(11)).foregroundStyle(Palette.gris)
                            .truncationMode(.middle).lineLimit(1)
                        Text("It holds this device’s keys and the cache. To use Klav here again you sign in with your emergency kit.")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(SquareToggleStyle())
                if let problem = installer.problems[.uninstall] { Notice(text: problem) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                        .keyboardShortcut(.cancelAction)
                    Button(installer.busy == .uninstall ? "Uninstalling…" : "Uninstall") {
                        Task {
                            if await installer.uninstall(engine: model.engine, deleteHome: deleteHome) {
                                finished = true
                                model.refresh()
                            }
                        }
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                    .disabled(installer.busy != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Palette.papel)
    }
}

private struct Line: View {
    let text: Text
    init(_ key: LocalizedStringKey) { text = Text(key) }
    @_disfavoredOverload
    init(_ string: String) { text = Text(verbatim: string) }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Rectangle().fill(Palette.tinta).frame(width: 8, height: 1).offset(y: -4)
            text.font(.ui(13)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
