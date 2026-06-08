import SwiftUI

/// The only View. It is intentionally "dumb": it observes AuthManager and renders
/// state, but contains no OAuth/PKCE logic of its own.
struct ContentView: View {
    @EnvironmentObject private var auth: AuthManager

    var body: some View {
        VStack(spacing: 24) {
            Text("OAuth 2.0 + PKCE Demo")
                .font(.title2).bold()

            if auth.isAuthenticated {
                // --- Logged-in state ---
                Text(auth.username.map { "Signed in as \($0)" } ?? "Signed in")
                    .font(.headline)

                Button("Call /me") {
                    Task { await auth.fetchMe() }
                }
                .buttonStyle(.borderedProminent)

                Button("Logout", role: .destructive) {
                    auth.logout()
                }
                .buttonStyle(.bordered)
            } else {
                // --- Logged-out state ---
                Button("Sign in") {
                    auth.login()
                }
                .buttonStyle(.borderedProminent)
            }

            if let error = auth.lastError {
                Text(error)
                    .font(.footnote)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }
        }
        .padding()
    }
}

#Preview {
    ContentView().environmentObject(AuthManager())
}
