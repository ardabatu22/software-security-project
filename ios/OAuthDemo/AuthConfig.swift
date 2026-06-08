import Foundation

/// All client-side configuration in one place (mirrors the backend's hardcoded values).
/// Keeping this separate from the Views and from AuthManager makes the demo easy to explain.
enum AuthConfig {

    /// Base URL of the Spring Boot backend.
    /// `localhost` works on the iOS Simulator because the Simulator shares the Mac's network.
    /// (On a physical device this would need to be the Mac's LAN IP instead.)
    static let backendBaseURL = URL(string: "http://localhost:8080")!

    /// The one public client this backend recognizes.
    static let clientID = "ios-demo-client"

    /// The full redirect URI registered for this client.
    static let redirectURI = "com.example.oauthdemo://callback"

    /// Just the scheme portion of the redirect URI.
    /// ASWebAuthenticationSession uses this to know which redirect to intercept.
    static let callbackURLScheme = "com.example.oauthdemo"
}
