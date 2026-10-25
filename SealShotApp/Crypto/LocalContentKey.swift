import Foundation
import Security
import CryptoKit

final class LocalContentKey {
    private let accountPrefix = "sealshot.local.content-key.v1."
    private let service = "com.sealshot.standalone"

    func load(evidenceID: String) throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountPrefix + evidenceID,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 else {
            throw SealShotFailure.keychain(status)
        }
        return SymmetricKey(data: bytes)
    }

    func loadOrCreate(evidenceID: String) throws -> SymmetricKey {
        let account = accountPrefix + evidenceID
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 {
            return SymmetricKey(data: bytes)
        }
        guard status == errSecItemNotFound else { throw SealShotFailure.keychain(status) }
        var bytes = Data(count: 32)
        let rng = bytes.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, 32, base)
        }
        guard rng == errSecSuccess else { throw SealShotFailure.cryptography }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecDuplicateItem { return try loadOrCreate(evidenceID: evidenceID) }
        guard addStatus == errSecSuccess else { throw SealShotFailure.keychain(addStatus) }
        return SymmetricKey(data: bytes)
    }
}
