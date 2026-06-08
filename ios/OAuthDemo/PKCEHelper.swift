import Foundation
import CryptoKit

/// PKCE (RFC 7636) helper: generates the high-entropy `code_verifier` and derives the
/// `code_challenge = BASE64URL( SHA256( code_verifier ) )` using CryptoKit.
///
/// This is the client side of the exact computation the backend re-runs at /token time.
enum PKCEHelper {

    /// Generates a cryptographically random `code_verifier`.
    /// 32 random bytes -> base64url -> 43 characters, which is within the RFC 7636
    /// allowed length range of 43..128 unreserved characters.
    static func generateCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncodedString()
    }

    /// Derives the S256 `code_challenge` from a `code_verifier`.
    static func codeChallenge(for verifier: String) -> String {
        let hash = SHA256.hash(data: Data(verifier.utf8))
        return Data(hash).base64URLEncodedString()
    }
}

extension Data {
    /// Base64URL encoding (RFC 4648 §5) with padding stripped: `+`->`-`, `/`->`_`, no `=`.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
