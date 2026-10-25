import SwiftUI

@main
struct SealShotApp: App {
    @StateObject private var vault = LocalVault()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vault)
        }
    }
}
