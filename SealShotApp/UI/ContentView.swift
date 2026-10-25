import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var vault: LocalVault
    @StateObject private var camera = LiveCamera()
    @State private var jobLabel = ""
    @State private var showingCamera = false
    @State private var errorMessage: String?
    @State private var previewImage: UIImage?
    @State private var showingPreview = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("SealShot", systemImage: "camera.aperture")
                            .font(.largeTitle.bold())
                        Text("Standalone encrypted evidence capture")
                            .font(.subheadline)
                        Text("Local integrity only · Not server attested · Device time unverified")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 12)
                }
                Section("Capture") {
                    TextField("Job label (optional)", text: $jobLabel)
                        .textInputAutocapitalization(.words)
                    Button {
                        showingCamera = true
                    } label: {
                        Label("Open live camera", systemImage: "camera.fill")
                    }
                }
                Section("Encrypted evidence (\(vault.items.count))") {
                    if vault.items.isEmpty {
                        Text("No evidence captured yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(vault.items) { item in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(item.id).font(.caption.monospaced())
                                .lineLimit(1)
                            Text(item.createdAt, style: .date)
                                .font(.caption).foregroundStyle(.secondary)
                            Button {
                                do {
                                    previewImage = UIImage(data: try vault.open(item))
                                    showingPreview = previewImage != nil
                                } catch { errorMessage = error.localizedDescription }
                            } label: {
                                Label("Verify and view on this iPhone", systemImage: "checkmark.shield")
                            }
                            ShareLink(item: item.url) {
                                Label("Export encrypted evidence", systemImage: "square.and.arrow.up")
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                Section("Important") {
                    Text("Each photograph is encrypted with a separate key stored only on this iPhone. If the app is deleted or this phone is lost, the photographs may become permanently unrecoverable. Do not rely on this experimental build as your only evidence archive.")
                        .font(.footnote)
                    Text("Exported files do not include decryption keys. A matching signature proves local cryptographic consistency, not camera authenticity or independently trusted identity.")
                        .font(.footnote)
                }
            }
            .navigationTitle("SealShot")
            .sheet(isPresented: $showingCamera) {
                NavigationStack {
                    VStack(spacing: 16) {
                        CameraPreview(session: camera.session)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                            .frame(maxHeight: .infinity)
                        Button {
                            camera.capture()
                        } label: {
                            Label("Capture and seal", systemImage: "circle.inset.filled")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!camera.ready || camera.isCapturing)
                        .padding(.horizontal)
                    }
                    .padding()
                    .navigationTitle("Live Camera")
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Close") { showingCamera = false }
                        }
                    }
                    .task { await camera.start() }
                    .onDisappear { camera.stop() }
                    .onChange(of: camera.capturedJPEG) { _, jpeg in
                        guard let jpeg else { return }
                        do {
                            try vault.save(jpeg: jpeg, jobLabel: jobLabel)
                            showingCamera = false
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                    .onChange(of: camera.errorMessage) { _, message in
                        if let message { errorMessage = message }
                    }
                }
            }
            .sheet(isPresented: $showingPreview) {
                NavigationStack {
                    Group {
                        if let previewImage {
                            Image(uiImage: previewImage)
                                .resizable().scaledToFit()
                                .padding()
                        }
                    }
                    .navigationTitle("Locally verified photo")
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") { showingPreview = false; previewImage = nil }
                        }
                    }
                }
            }
            .alert("SealShot", isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "Unknown error")
            }
        }
    }
}
