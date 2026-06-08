import Foundation
import AuthenticationServices

/// The entire OAuth 2.0 Authorization Code + PKCE client lives here, isolated from the
/// SwiftUI Views. Views only observe the @Published state below.
///
/// Flow:
///   login() -> build /authorize URL with code_challenge + state
///           -> ASWebAuthenticationSession opens it, captures the redirect
///           -> verify state, extract code
///           -> POST /token with code + code_verifier
///           -> store JWT in Keychain, set isAuthenticated
///   fetchMe() -> GET /me with Bearer JWT, publish username
///   logout()  -> clear Keychain + state
final class AuthManager: NSObject, ObservableObject {

    // MARK: - Observable state (the Views react to these)
    @Published var isAuthenticated = false
    @Published var username: String?
    @Published var lastError: String?

    // MARK: - Transient per-login state
    private var webAuthSession: ASWebAuthenticationSession?  // strong ref so it isn't deallocated mid-flight
    private var currentState: String?                        // the state we sent (for CSRF check)
    private var currentVerifier: String?                     // the PKCE verifier for this login

    override init() {
        super.init()
        // If a token is already in the Keychain from a previous run, consider us signed in.
        if KeychainHelper.read() != nil {
            isAuthenticated = true
        }
    }

    // MARK: - Login

    /// Starts the authorization flow. Called from the "Sign in" button (main thread).
    func login() {
        lastError = nil

        // 1. PKCE: make a verifier and its S256 challenge.
        let verifier = PKCEHelper.generateCodeVerifier()
        let challenge = PKCEHelper.codeChallenge(for: verifier)
        currentVerifier = verifier

        // 2. Anti-CSRF: a random, unguessable state we will require back unchanged.
        let state = UUID().uuidString
        currentState = state

        // 3. Build the /authorize URL.
        var components = URLComponents(
            url: AuthConfig.backendBaseURL.appendingPathComponent("authorize"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: AuthConfig.clientID),
            URLQueryItem(name: "redirect_uri", value: AuthConfig.redirectURI),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        guard let authURL = components.url else {
            lastError = "Failed to build the authorize URL."
            return
        }

        // 4. Launch the system auth session. It opens a secure in-app browser and,
        //    when the backend redirects to our custom scheme, hands us the callback URL.
        let session = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: AuthConfig.callbackURLScheme
        ) { [weak self] callbackURL, error in
            // Apple invokes this completion handler on the main thread.
            guard let self else { return }
            if let error {
                // Includes the user tapping Cancel (ASWebAuthenticationSessionError.canceledLogin).
                self.lastError = "Authorization canceled or failed: \(error.localizedDescription)"
                return
            }
            guard let callbackURL else {
                self.lastError = "No callback URL was returned."
                return
            }
            self.handleCallback(callbackURL)
        }
        // The session needs a window to present from (bridge below).
        session.presentationContextProvider = self
        // Don't reuse cookies across runs — keeps the demo clean and repeatable.
        session.prefersEphemeralWebBrowserSession = true
        webAuthSession = session
        session.start()
    }

    /// Parses the redirect, verifies state, and kicks off the token exchange.
    private func handleCallback(_ url: URL) {
        guard
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let items = components.queryItems
        else {
            lastError = "Malformed callback URL."
            return
        }

        let returnedState = items.first { $0.name == "state" }?.value
        let code = items.first { $0.name == "code" }?.value

        // CSRF protection: the returned state MUST equal the one we sent.
        guard returnedState == currentState else {
            lastError = "State mismatch — possible CSRF. Aborting."
            return
        }
        guard let code else {
            lastError = "No authorization code in the callback."
            return
        }
        guard let verifier = currentVerifier else {
            lastError = "Missing code_verifier (internal error)."
            return
        }

        Task { await exchangeCodeForToken(code: code, verifier: verifier) }
    }

    /// POSTs the code + code_verifier to /token and stores the returned JWT.
    /// Marked @MainActor so that, after the network await, publishing @Published
    /// properties happens back on the main thread.
    @MainActor
    private func exchangeCodeForToken(code: String, verifier: String) async {
        do {
            var request = URLRequest(url: AuthConfig.backendBaseURL.appendingPathComponent("token"))
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            // Standard OAuth token request body (form-encoded).
            let body = "code=\(code)&code_verifier=\(verifier)&client_id=\(AuthConfig.clientID)"
            request.httpBody = body.data(using: .utf8)

            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                let serverMsg = String(data: data, encoding: .utf8) ?? "unknown error"
                lastError = "Token request failed: \(serverMsg)"
                return
            }

            let token = try JSONDecoder().decode(TokenResponse.self, from: data)
            KeychainHelper.save(token.access_token)
            isAuthenticated = true
            lastError = nil
        } catch {
            lastError = "Token exchange error: \(error.localizedDescription)"
        }
    }

    // MARK: - Protected resource

    /// Calls GET /me with the Bearer JWT and publishes the username.
    @MainActor
    func fetchMe() async {
        guard let token = KeychainHelper.read() else {
            lastError = "No token stored. Please sign in."
            isAuthenticated = false
            return
        }
        do {
            var request = URLRequest(url: AuthConfig.backendBaseURL.appendingPathComponent("me"))
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                lastError = "/me: no HTTP response."
                return
            }
            if http.statusCode == 401 {
                // Token invalid or expired -> drop it and force re-login.
                lastError = "Token invalid or expired. Please sign in again."
                logout()
                return
            }
            let me = try JSONDecoder().decode(MeResponse.self, from: data)
            username = me.username
            lastError = nil
        } catch {
            lastError = "/me error: \(error.localizedDescription)"
        }
    }

    // MARK: - Logout

    func logout() {
        KeychainHelper.delete()
        isAuthenticated = false
        username = nil
    }
}

// MARK: - Presentation anchor bridge

/// ASWebAuthenticationSession needs to know which window to present its sheet from.
/// We return the app's active key window.
extension AuthManager: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let scene = UIApplication.shared.connectedScenes
            .first { $0.activationState == .foregroundActive } as? UIWindowScene
        return scene?.windows.first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}

// MARK: - Decodable response models (match the backend JSON)

private struct TokenResponse: Decodable {
    let access_token: String
}

private struct MeResponse: Decodable {
    let id: String
    let username: String
}
