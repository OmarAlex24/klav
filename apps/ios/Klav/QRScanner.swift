import AVFoundation
import CoreImage
import SwiftUI
import UIKit

/// Reads the QR codes in a picture (a screenshot of Google
/// Authenticator's Transfer accounts screen). Core Image, on the device:
/// the picture goes nowhere.
enum QRReader {
    static func messages(in data: Data) -> [String] {
        guard let image = CIImage(data: data, options: [.applyOrientationProperty: true]) else { return [] }
        return messages(in: image)
    }

    static func messages(in image: CIImage) -> [String] {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return (detector?.features(in: image) ?? []).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}

/// Whether the camera can be used to scan, and asks once.
enum CameraAccess {
    case ready, denied, missing

    static func check() async -> CameraAccess {
        guard AVCaptureDevice.default(for: .video) != nil else { return .missing }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return .ready
        case .notDetermined: return await AVCaptureDevice.requestAccess(for: .video) ? .ready : .denied
        default: return .denied
        }
    }
}

/// The camera, reading QR codes as they come into view. Each text is
/// reported once.
struct QRCameraView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> QRCameraController {
        let controller = QRCameraController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ controller: QRCameraController, context: Context) {
        controller.onCode = onCode
    }
}

final class QRCameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "dev.klav.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var seen: Set<String> = []

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let session = session
        queue.async { if !session.isRunning { session.startRunning() } }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = session
        queue.async { if session.isRunning { session.stopRunning() } }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        for object in objects {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                  let text = code.stringValue, seen.insert(text).inserted else { continue }
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            onCode?(text)
        }
    }
}

/// The camera sheet: the picture, a square to aim, how many QR codes are
/// in and which are missing. Closes by hand: an export can have several.
struct QRScanSheet: View {
    let added: Int
    let missing: [ImportMissingInfo]
    let problem: String?
    let onCode: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var access: CameraAccess?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Title("Scan the QR codes", size: 22)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.horizontal, 20)
            .frame(minHeight: 64)
            .overlay(alignment: .bottom) { Rule() }
            VStack(alignment: .leading, spacing: 14) {
                Text("Point the camera at each QR code on the other phone’s Transfer accounts screen. Klav adds every one it reads.")
                    .font(.ui(15)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                camera
                    .aspectRatio(1, contentMode: .fit)
                    .crossCorners()
                    .frame(maxWidth: .infinity)
                Text(added == 0 ? String(localized: "No QR code read yet.") : String(localized: "\(added) QR codes added"))
                    .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                    .accessibilityIdentifier("scan-count")
                ForEach(missing, id: \.size) { batch in
                    Notice(text: missingText(batch), tone: .info)
                }
                if let problem { Notice(text: problem) }
            }
            .padding(20)
            Spacer(minLength: 0)
        }
        .background(Palette.papel)
        .task { access = await CameraAccess.check() }
    }

    @ViewBuilder private var camera: some View {
        switch access {
        case .ready:
            QRCameraView(onCode: onCode)
                .overlay(Rectangle().strokeBorder(Palette.papel.opacity(0.9), lineWidth: 2).padding(40))
                .accessibilityLabel("Camera")
        case .denied:
            unavailable(String(localized: "Klav can’t use the camera. Turn it on in the iPhone’s Settings › Klav, or choose screenshots instead."),
                        settings: true)
        case .missing:
            unavailable(String(localized: "This iPhone has no camera available. Choose screenshots of the QR codes, or paste their links."),
                        settings: false)
        case nil:
            Palette.niebla
        }
    }

    private func unavailable(_ text: String, settings: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(text).font(.ui(15)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if settings {
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                }
                .buttonStyle(SecondaryButtonStyle(compact: true))
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Palette.niebla)
    }
}

/// "This export has 3 QR codes and 2 aren’t here yet."
func missingText(_ batch: ImportMissingInfo) -> String {
    String(localized: "This export has \(Int(batch.size)) QR codes and \(batch.missing.count) aren’t here yet. Add them too.")
}
