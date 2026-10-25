import Foundation
import Security
import CryptoKit

struct CaptureManifest: Codable {
    let protocolVersion: Int
    let evidenceID: String
    let ownerID: String
    let jobLabel: String
    let originalSHA256: String
    let originalLength: Int
    let ciphertextSHA256: String
    let nonceBase64: String
    let captureMethod: String
    let deviceClaimedAt: String
    let timeAssurance: String
    let attestationAssurance: String
    let signingAssurance: String
}

struct EvidenceEnvelope: Codable {
    let format: String
    let manifestBase64: String
    let signatureBase64: String
    let publicKeyX963Base64: String
    let nonceBase64: String
    let ciphertextAndTagBase64: String
}

struct EvidenceSealer {
    private let signer = SecureSigner()
    private let keyStore = LocalContentKey()
    private let signatureDomain = Data("SealShot/standalone-local/v1\0".utf8)

    func seal(jpeg: Data, ownerID: String, jobLabel: String) throws -> (id: String, bytes: Data) {
        guard jpeg.count > 4, jpeg.count <= 100 * 1024 * 1024,
              jpeg.prefix(2) == Data([0xFF, 0xD8]),
              jpeg.suffix(2) == Data([0xFF, 0xD9]) else {
            throw SealShotFailure.invalidEvidence
        }
        let evidenceID = UUID().uuidString.lowercased()
        let key = try keyStore.loadOrCreate(evidenceID: evidenceID)
        let nonce = AES.GCM.Nonce()
        let aad = Data("SealShot/local-photo/v1/\(evidenceID)".utf8)
        let sealed = try AES.GCM.seal(jpeg, using: key, nonce: nonce, authenticating: aad)
        let ciphertextAndTag = sealed.ciphertext + sealed.tag
        let claimedAt = ISO8601DateFormatter().string(from: Date())
        let manifest = CaptureManifest(
            protocolVersion: 1,
            evidenceID: evidenceID,
            ownerID: ownerID,
            jobLabel: jobLabel,
            originalSHA256: Data(SHA256.hash(data: jpeg)).hexString,
            originalLength: jpeg.count,
            ciphertextSHA256: Data(SHA256.hash(data: ciphertextAndTag)).hexString,
            nonceBase64: Data(nonce).base64EncodedString(),
            captureMethod: "AVFoundation-live-camera-client-asserted",
            deviceClaimedAt: claimedAt,
            timeAssurance: "DEVICE_CLOCK_UNVERIFIED",
            attestationAssurance: "NOT_VERIFIED",
            signingAssurance: "LOCAL_SECURE_ENCLAVE_KEY_UNENROLLED"
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let manifestData = try encoder.encode(manifest)
        let signingKey = try signer.key()
        let signature = try signer.sign(signatureDomain + manifestData, key: signingKey)
        let point = try signer.publicPoint(key: signingKey)
        let envelope = EvidenceEnvelope(
            format: "SealShot-Standalone-Local-v1",
            manifestBase64: manifestData.base64EncodedString(),
            signatureBase64: signature.base64EncodedString(),
            publicKeyX963Base64: point.base64EncodedString(),
            nonceBase64: Data(nonce).base64EncodedString(),
            ciphertextAndTagBase64: ciphertextAndTag.base64EncodedString()
        )
        return (evidenceID, try encoder.encode(envelope))
    }

    func open(_ envelopeBytes: Data) throws -> Data {
        let envelope = try JSONDecoder().decode(EvidenceEnvelope.self, from: envelopeBytes)
        guard envelope.format == "SealShot-Standalone-Local-v1",
              let manifestBytes = Data(base64Encoded: envelope.manifestBase64),
              let signature = Data(base64Encoded: envelope.signatureBase64),
              let publicPoint = Data(base64Encoded: envelope.publicKeyX963Base64),
              let nonceData = Data(base64Encoded: envelope.nonceBase64),
              let ciphertextAndTag = Data(base64Encoded: envelope.ciphertextAndTagBase64),
              nonceData.count == 12, ciphertextAndTag.count >= 16 else {
            throw SealShotFailure.invalidEvidence
        }
        let manifest = try JSONDecoder().decode(CaptureManifest.self, from: manifestBytes)
        guard manifest.protocolVersion == 1,
              !manifest.evidenceID.isEmpty,
              !manifest.ownerID.isEmpty,
              manifest.originalLength > 0,
              manifest.originalLength <= 100 * 1024 * 1024,
              manifest.captureMethod == "AVFoundation-live-camera-client-asserted",
              manifest.timeAssurance == "DEVICE_CLOCK_UNVERIFIED",
              manifest.attestationAssurance == "NOT_VERIFIED",
              manifest.signingAssurance == "LOCAL_SECURE_ENCLAVE_KEY_UNENROLLED",
              Data(SHA256.hash(data: ciphertextAndTag)).hexString == manifest.ciphertextSHA256,
              manifest.nonceBase64 == envelope.nonceBase64 else {
            throw SealShotFailure.invalidEvidence
        }
        // A self-contained exported envelope is not a trust anchor. For local
        // viewing, require the embedded key to match THIS app's own Secure
        // Enclave key. This prevents key-substitution + re-signing attacks.
        let localSigningKey = try signer.key()
        guard publicPoint == (try signer.publicPoint(key: localSigningKey)) else {
            throw SealShotFailure.invalidEvidence
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var keyError: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(publicPoint as CFData, attributes as CFDictionary, &keyError) else {
            throw SealShotFailure.invalidEvidence
        }
        var verifyError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(
            publicKey, .ecdsaSignatureMessageX962SHA256,
            (signatureDomain + manifestBytes) as CFData,
            signature as CFData, &verifyError
        ) else { throw SealShotFailure.invalidEvidence }
        let contentKey = try keyStore.load(evidenceID: manifest.evidenceID)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertextAndTag.dropLast(16),
            tag: ciphertextAndTag.suffix(16)
        )
        let plaintext = try AES.GCM.open(
            sealedBox, using: contentKey,
            authenticating: Data("SealShot/local-photo/v1/\(manifest.evidenceID)".utf8)
        )
        guard plaintext.count == manifest.originalLength,
              Data(SHA256.hash(data: plaintext)).hexString == manifest.originalSHA256 else {
            throw SealShotFailure.invalidEvidence
        }
        return plaintext
    }

}

private extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
