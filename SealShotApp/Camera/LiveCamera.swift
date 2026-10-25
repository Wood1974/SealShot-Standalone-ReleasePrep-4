import SwiftUI
import AVFoundation

@MainActor
final class LiveCamera: NSObject, ObservableObject, AVCapturePhotoCaptureDelegate {
    let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private let sessionQueue = DispatchQueue(label: "com.sealshot.standalone.camera.session")
    // Accessed only on sessionQueue.
    private var configured = false

    @Published private(set) var ready = false
    @Published private(set) var isCapturing = false
    @Published var errorMessage: String?
    @Published var capturedJPEG: Data?

    func start() async {
        let permission = AVCaptureDevice.authorizationStatus(for: .video)
        if permission == .notDetermined {
            guard await AVCaptureDevice.requestAccess(for: .video) else {
                errorMessage = "Camera access is required. Enable it in Settings."
                return
            }
        } else if permission != .authorized {
            errorMessage = "Camera access is disabled in Settings."
            return
        }
        // AVFoundation recommends configuring and starting a capture session
        // off the main thread. Never block the SwiftUI event loop here.
        sessionQueue.async { [self] in
            do {
                if !configured {
                    session.beginConfiguration()
                    session.sessionPreset = .photo
                    guard let device = AVCaptureDevice.default(
                        .builtInWideAngleCamera, for: .video, position: .back
                    ) else {
                        session.commitConfiguration()
                        throw SealShotFailure.cameraUnavailable
                    }
                    let input = try AVCaptureDeviceInput(device: device)
                    guard session.canAddInput(input), session.canAddOutput(output) else {
                        session.commitConfiguration()
                        throw SealShotFailure.cameraUnavailable
                    }
                    session.addInput(input)
                    session.addOutput(output)
                    session.commitConfiguration()
                    configured = true
                }
                if !session.isRunning { session.startRunning() }
                let running = session.isRunning
                Task { @MainActor in self.ready = running }
            } catch {
                let message = error.localizedDescription
                Task { @MainActor in self.errorMessage = message; self.ready = false }
            }
        }
    }

    func stop() {
        ready = false
        sessionQueue.async { [self] in
            if session.isRunning { session.stopRunning() }
        }
    }

    func capture() {
        guard ready, !isCapturing else { return }
        isCapturing = true
        capturedJPEG = nil
        let settings = AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
        output.capturePhoto(with: settings, delegate: self)
    }

    nonisolated func photoOutput(_ output: AVCapturePhotoOutput,
                                 didFinishProcessingPhoto photo: AVCapturePhoto,
                                 error: Error?) {
        let bytes = photo.fileDataRepresentation()
        let message = error?.localizedDescription
        Task { @MainActor in
            self.isCapturing = false
            if let message { self.errorMessage = message }
            else if let bytes { self.capturedJPEG = bytes }
            else { self.errorMessage = "Unable to read camera JPEG." }
        }
    }
}

struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.videoLayer.session = session
        view.videoLayer.videoGravity = .resizeAspectFill
        return view
    }

    func updateUIView(_ view: PreviewView, context: Context) {
        view.videoLayer.session = session
    }
}

final class PreviewView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var videoLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}
