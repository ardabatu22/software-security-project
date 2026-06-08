import Foundation
import Security

/// Minimal wrapper around the iOS Keychain for storing the JWT access token.
///
/// We use the Keychain (not UserDefaults) because it is the OS-provided secure,
/// encrypted store for secrets — a key point for the security write-up.
enum KeychainHelper {

    // A generic-password item is identified by (service, account).
    private static let service = "com.example.oauthdemo"
    private static let account = "access_token"

    /// Stores (or replaces) the access token.
    static func save(_ token: String) {
        let data = Data(token.utf8)

        // Identify the item.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        // Delete any existing item first so we always store a single fresh value.
        SecItemDelete(query as CFDictionary)

        var attributes = query
        attributes[kSecValueData as String] = data
        SecItemAdd(attributes as CFDictionary, nil)
    }

    /// Reads the stored access token, or nil if none is present.
    static func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Deletes the stored access token (used on logout / token-expiry).
    static func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
