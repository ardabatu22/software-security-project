import SwiftUI

/// App entry point. Creates the single AuthManager and injects it into the
/// environment so ContentView (and any future View) can observe it.
///
/// NOTE: If your Xcode project generated this file with a different struct name
/// (it matches your project name), either rename your generated struct to this,
/// or just copy the `@StateObject` + `.environmentObject(...)` lines into yours.
@main
struct OAuthDemoApp: App {
    @StateObject private var auth = AuthManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
        }
    }
}
