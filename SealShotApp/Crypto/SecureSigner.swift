import Foundation
import Security

enum SealShotFailure: LocalizedError {
    case cameraUnavailable, permissionDenied, keychain(OSStatus), cryptography, invalidEvidence, storage
    var errorDescription: String? {
        switch self {
        case .cameraUnavailable: return "Live camera is unavailable."
        case .permissionDenied: return "Camera permission was denied."
        case .keychain(let status): return "Secure key storage error (\(status))."
        case .cryptography: return "Evidence cryptography failed."
        case .invalidEvidence: return "Evidence file is invalid."
        case .storage: return "Unable to save evidence securely."
        }
    }
}

final class SecureSigner {
    private let tag = Data("com.sealshot.standalone.signing.v1".utf8)

    func key() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let existing = result {
            return existing as! SecKey
        }
        guard status == errSecItemNotFound else { throw SealShotFailure.keychain(status) }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage], &accessError
        ) else { throw SealShotFailure.cryptography }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw SealShotFailure.cryptography
        }
        return key
    }

    func sign(_ message: Data, key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
        ) else { throw SealShotFailure.cryptography }
        return signature as Data
    }

    func publicPoint(key: SecKey) throws -> Data {
        guard let pub = SecKeyCopyPublicKey(key) else { throw SealShotFailure.cryptography }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) else {
            throw SealShotFailure.cryptography
        }
        return data as Data
    }
}
