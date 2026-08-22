import SwiftUI

@main
struct NTWireApp: App {
    var body: some Scene {
        WindowGroup {
            ProfileListView()
        }
    }
}

private struct ProfileListView: View {
    @State private var profiles: [ServerProfile] = []
    @State private var selection: UUID?
    @State private var showingEditor = false

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                ForEach(profiles) { profile in
                    VStack(alignment: .leading) {
                        Text(profile.displayName)
                        Text(profile.serverURL.host ?? "")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .tag(profile.id)
                }
            }
            .navigationTitle("ntwire")
            .toolbar {
                Button("Add server", systemImage: "plus") { showingEditor = true }
            }
        } detail: {
            if let profile = profiles.first(where: { $0.id == selection }) {
                ProfileDetailView(profile: profile)
            } else {
                ContentUnavailableView("Select a server", systemImage: "network", description: Text("Add an ntwire server to begin."))
            }
        }
        .sheet(isPresented: $showingEditor) {
            ProfileEditor { profile in
                profiles.append(profile)
                selection = profile.id
            }
        }
    }
}

private struct ProfileDetailView: View {
    let profile: ServerProfile
    @State private var connectionState: ConnectionState = .disconnected

    var body: some View {
        List {
            Section("Connection") {
                LabeledContent("Server", value: profile.serverURL.host ?? profile.serverURL.absoluteString)
                LabeledContent("Authentication", value: profile.authenticationMethod.rawValue.uppercased())
                LabeledContent("State", value: label(for: connectionState))
                Button(connectionState == .disconnected ? "Authenticate" : "Disconnect") {
                    connectionState = connectionState == .disconnected
                        ? connectionState.applying(.connectRequested)
                        : connectionState.applying(.disconnectRequested)
                }
            }
            Section("Granted tunnels") {
                ContentUnavailableView("No grants loaded", systemImage: "lock", description: Text("Authenticate to retrieve the grants authorized by the ntwire server."))
            }
            Section("Diagnostics") {
                LabeledContent("Transport", value: "Not configured")
                LabeledContent("Relay", value: "Requires masque-relay-v1")
                Text("Diagnostics never display credentials, keys, session tokens, or private targets.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(profile.displayName)
    }

    private func label(for state: ConnectionState) -> String {
        switch state {
        case .disconnected: return "Disconnected"
        case .authenticating: return "Authenticating"
        case .configuringRelay: return "Configuring relay"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting"
        case .loginRequired: return "Login required"
        case .failed: return "Failed"
        }
    }
}

private struct ProfileEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State private var displayName = ""
    @State private var server = "https://"
    @State private var method: AuthenticationMethod = .oidc
    @State private var error: String?
    let onSave: (ServerProfile) -> Void

    var body: some View {
        NavigationStack {
            Form {
                TextField("Display name", text: $displayName)
                TextField("Server URL", text: $server)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                Picker("Authentication", selection: $method) {
                    ForEach(AuthenticationMethod.allCases, id: \.self) { method in
                        Text(method.rawValue.uppercased()).tag(method)
                    }
                }
                if let error {
                    Text(error).foregroundStyle(.red)
                }
            }
            .navigationTitle("Add server")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                }
            }
        }
    }

    private func save() {
        guard let url = URL(string: server) else {
            error = "Enter a valid HTTPS URL."
            return
        }
        do {
            let profile = try ServerProfile(displayName: displayName, serverURL: url, authenticationMethod: method)
            onSave(profile)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
