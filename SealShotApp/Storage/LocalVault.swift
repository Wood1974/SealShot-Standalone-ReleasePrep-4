import Foundation
import Combine

struct SavedEvidence: Identifiable {
    let id: String
    let url: URL
    let createdAt: Date
}

@MainActor
final class LocalVault: ObservableObject {
    @Published private(set) var items: [SavedEvidence] = []
    @Published var lastError: String?
    private let sealer = EvidenceSealer()
    private let ownerIDKey = "sealshot.standalone.owner.id"

    private var vaultDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Evidence", isDirectory: true)
    }

    init() { refresh() }

    private var ownerID: String {
        if let value = UserDefaults.standard.string(forKey: ownerIDKey) { return value }
        let value = UUID().uuidString.lowercased()
        UserDefaults.standard.set(value, forKey: ownerIDKey)
        return value
    }

    func save(jpeg: Data, jobLabel: String) throws {
        let (id, bytes) = try sealer.seal(
            jpeg: jpeg,
            ownerID: ownerID,
            jobLabel: String(jobLabel.prefix(128))
        )
        try FileManager.default.createDirectory(
            at: vaultDirectory, withIntermediateDirectories: true
        )
        let url = vaultDirectory.appendingPathComponent(id + ".sealshot")
        try bytes.write(to: url, options: [.atomic, .completeFileProtection])
        refresh()
    }

    func open(_ item: SavedEvidence) throws -> Data {
        // Do not let a renamed evidence file masquerade as a different ID.
        let bytes = try Data(contentsOf: item.url)
        let envelope = try JSONDecoder().decode(EvidenceEnvelope.self, from: bytes)
        guard let manifestBytes = Data(base64Encoded: envelope.manifestBase64),
              let manifest = try? JSONDecoder().decode(CaptureManifest.self, from: manifestBytes),
              manifest.evidenceID == item.id,
              manifest.ownerID == ownerID else {
            throw SealShotFailure.invalidEvidence
        }
        return try sealer.open(bytes)
    }

    func refresh() {
        let urls = (try? FileManager.default.contentsOfDirectory(
            at: vaultDirectory,
            includingPropertiesForKeys: [.creationDateKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        items = urls.filter { $0.pathExtension == "sealshot" }.map { url in
            let date = (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            return SavedEvidence(id: url.deletingPathExtension().lastPathComponent,
                                 url: url, createdAt: date)
        }.sorted { $0.createdAt > $1.createdAt }
    }
}
