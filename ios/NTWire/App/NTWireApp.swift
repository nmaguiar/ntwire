import SwiftUI
import UniformTypeIdentifiers

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
    @State private var editingProfile: ServerProfile?
    @State private var error: String?
    private let profileStore = JSONProfileStore(fileURL: Self.profileStoreURL)
    private let credentialStore = KeychainCredentialStore()

    private static let profileStoreURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("NTWire", isDirectory: true)
        .appendingPathComponent("profiles.json")

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
                .onDelete(perform: deleteProfiles)
            }
            .navigationTitle("ntwire")
            .toolbar {
                Button("Add server", systemImage: "plus") { showingEditor = true }
            }
        } detail: {
            if let profile = profiles.first(where: { $0.id == selection }) {
                ProfileDetailView(profile: profile, credentialStore: credentialStore, onEdit: { editingProfile = profile }, onUpdate: updateProfile)
            } else {
                ContentUnavailableView("Select a server", systemImage: "network", description: Text("Add an ntwire server to begin."))
            }
        }
        .sheet(isPresented: $showingEditor) {
            ProfileEditor { profile, keyChange in save(profile, keyChange: keyChange) }
        }
        .sheet(item: $editingProfile) { profile in
            ProfileEditor(profile: profile) { savedProfile, keyChange in
                save(savedProfile, keyChange: keyChange)
            }
        }
        .task { loadProfiles() }
        .alert("ntwire", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK", role: .cancel) { error = nil }
        } message: {
            Text(error ?? "")
        }
    }

    private func loadProfiles() {
        do {
            profiles = try profileStore.load()
            selection = profiles.first?.id
        } catch {
            self.error = "Could not load profiles: \(error.localizedDescription)"
        }
    }

    private func save(_ profile: ServerProfile, keyChange: SSHKeyChange) {
        do {
            if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
                profiles[index] = profile
            } else {
                profiles.append(profile)
            }
            try profileStore.save(profiles)
            switch keyChange {
            case .unchanged: break
            case .replace(let value):
                try credentialStore.write(value, account: ProfileCredentialAccount.sshPrivateKey(for: profile.id))
                try credentialStore.remove(account: ProfileCredentialAccount.sessionToken(for: profile.id))
            case .remove:
                try credentialStore.remove(account: ProfileCredentialAccount.sshPrivateKey(for: profile.id))
                try credentialStore.remove(account: ProfileCredentialAccount.sessionToken(for: profile.id))
            }
            selection = profile.id
        } catch {
            self.error = "Could not save profile: \(error.localizedDescription)"
        }
    }

    /// Persists an in-place profile change, such as a certificate pin learned
    /// on first connect. Never touches Keychain-stored credentials.
    private func updateProfile(_ profile: ServerProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        profiles[index] = profile
        do { try profileStore.save(profiles) }
        catch { self.error = "Could not save profile: \(error.localizedDescription)" }
    }

    private func deleteProfiles(at offsets: IndexSet) {
        do {
            let removed = offsets.map { profiles[$0] }
            profiles.remove(atOffsets: offsets)
            try profileStore.save(profiles)
            for profile in removed {
                try credentialStore.remove(account: ProfileCredentialAccount.sshPrivateKey(for: profile.id))
                try credentialStore.remove(account: ProfileCredentialAccount.wireGuardPrivateKey(for: profile.id))
                try credentialStore.remove(account: ProfileCredentialAccount.sessionToken(for: profile.id))
            }
            selection = profiles.first?.id
        } catch {
            self.error = "Could not delete profile: \(error.localizedDescription)"
        }
    }
}

/// Captures a certificate reported untrusted on the URLSession delegate
/// queue so it can be read back on the calling task after `await` resumes,
/// without handing a non-Sendable View closure across that thread boundary.
private final class UntrustedCertBox: @unchecked Sendable {
    private(set) var value: UntrustedServerCertificateError?
    func set(_ error: UntrustedServerCertificateError) { value = error }
}

/// Records every server-trust challenge `PinningURLSessionDelegate` saw
/// during one connection attempt, so a non-pin failure can say whether the
/// delegate was consulted at all — distinguishing "never reached the TLS
/// layer" from "trusted the certificate, then failed for another reason"
/// instead of surfacing only the system's generic TLS error text.
private final class ChallengeLog: @unchecked Sendable {
    private(set) var count = 0
    private(set) var lastAccepted: Bool?
    func record(_ number: Int, _ accepted: Bool) {
        count = number
        lastAccepted = accepted
    }
}

/// Wraps a non-pin authentication failure with what the pinning delegate
/// observed, so the on-screen message carries that detail instead of just
/// the system's often-uninformative TLS error text.
private struct DiagnosableTransportError: Error, LocalizedError {
    let underlying: Error
    let challengeCount: Int
    let lastAccepted: Bool?

    var errorDescription: String? {
        let detail: String
        switch (challengeCount, lastAccepted) {
        case (0, _): detail = "the certificate check was never reached"
        case (_, true): detail = "the certificate was trusted, then the connection failed anyway"
        default: detail = "the certificate check ran \(challengeCount) time(s) and rejected it"
        }
        return "\(underlying.localizedDescription) (\(detail))"
    }
}

/// A certificate awaiting the user's explicit trust decision, bridging the
/// SwiftUI alert back into the suspended `authenticate()` task.
private struct PendingTrust {
    let error: UntrustedServerCertificateError
    let continuation: CheckedContinuation<Bool, Never>
}

private struct ProfileDetailView: View {
    let profile: ServerProfile
    let credentialStore: any CredentialStore
    let onEdit: () -> Void
    let onUpdate: (ServerProfile) -> Void
    @State private var connectionState: ConnectionState = .disconnected
    @State private var result: AuthenticationResponse?
    @State private var error: String?
    @State private var passphrase = ""
    @State private var showingPassphrasePrompt = false
    @State private var pendingTrust: PendingTrust?
    @State private var probeResult: String?
    @State private var probing = false

    var body: some View {
        List {
            Section("Connection") {
                LabeledContent("Server", value: profile.serverURL.host ?? profile.serverURL.absoluteString)
                LabeledContent("Authentication", value: profile.authenticationMethod.rawValue.uppercased())
                LabeledContent("State", value: label(for: connectionState))
                Button(connectionState == .disconnected ? "Authenticate" : "Disconnect") {
                    if connectionState == .disconnected { authenticate() }
                    else { disconnect() }
                }
                .disabled(connectionState == .authenticating)
            }
            Section("Granted tunnels") {
                if let result, !result.tunnels.isEmpty {
                    ForEach(result.tunnels) { tunnel in
                        LabeledContent(tunnel.name, value: tunnel.targetHint)
                    }
                } else {
                    ContentUnavailableView("No grants loaded", systemImage: "lock", description: Text("Authenticate to retrieve the grants authorized by the ntwire server."))
                }
            }
            Section("Diagnostics") {
                LabeledContent("Transport", value: "Not configured")
                LabeledContent("Relay", value: "Requires masque-relay-v1")
                LabeledContent("Certificate pin", value: profile.certificatePin ?? "Learned on first connect")
                Button(probing ? "Testing…" : "Test connection (GET /v1/info)") { probeServerInfo() }
                    .disabled(probing)
                if let probeResult {
                    Text(probeResult).font(.footnote).foregroundStyle(.secondary)
                }
                Text("Diagnostics never display credentials, keys, session tokens, or private targets.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(profile.displayName)
        .toolbar { Button("Edit", action: onEdit) }
        .alert("SSH key passphrase", isPresented: $showingPassphrasePrompt) {
            SecureField("Passphrase", text: $passphrase)
            Button("Authenticate") { authenticate(passphrase: passphrase) }
            Button("Cancel", role: .cancel) { passphrase = "" }
        } message: {
            Text("Enter the passphrase for this SSH key. It is used only for this authentication request and is never stored.")
        }
        .alert("Authentication failed", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK", role: .cancel) { error = nil }
        } message: { Text(error ?? "") }
        .alert(
            "Untrusted certificate",
            isPresented: Binding(get: { pendingTrust != nil }, set: { if !$0 { resolvePendingTrust(false) } })
        ) {
            Button("Trust") { resolvePendingTrust(true) }
            Button("Cancel", role: .cancel) { resolvePendingTrust(false) }
        } message: {
            Text(pendingTrust?.error.errorDescription ?? "")
        }
    }

    /// Resolves the alert's continuation exactly once; the second call this
    /// produces (SwiftUI dismissing the alert after a button already
    /// resolved it) becomes a no-op because `pendingTrust` is already nil.
    private func resolvePendingTrust(_ trust: Bool) {
        pendingTrust?.continuation.resume(returning: trust)
        pendingTrust = nil
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

    private func authenticate(passphrase: String? = nil) {
        connectionState = connectionState.applying(.connectRequested)
        Task {
            do {
                guard let privateKey = try credentialStore.read(account: ProfileCredentialAccount.sshPrivateKey(for: profile.id)) else {
                    throw SSHAuthenticationError.missingPrivateKey
                }
                let wireGuardKey: Data
                if let saved = try credentialStore.read(account: ProfileCredentialAccount.wireGuardPrivateKey(for: profile.id)) {
                    wireGuardKey = saved
                } else {
                    wireGuardKey = WireGuardIdentity.makePrivateKey()
                    try credentialStore.write(wireGuardKey, account: ProfileCredentialAccount.wireGuardPrivateKey(for: profile.id))
                }
                let response = try await performAuthentication(privateKey: privateKey, passphrase: passphrase, wireGuardKey: wireGuardKey)
                if !response.token.isEmpty {
                    try credentialStore.write(Data(response.token.utf8), account: ProfileCredentialAccount.sessionToken(for: profile.id))
                }
                result = response
                self.passphrase = ""
                connectionState = connectionState.applying(.authenticationSucceeded)
            } catch SSHAuthenticationError.passphraseRequired {
                connectionState = .disconnected
                showingPassphrasePrompt = true
            } catch {
                connectionState = connectionState.applying(.failed(error.localizedDescription))
                self.error = error.localizedDescription
            }
        }
    }

    /// Authenticates using the profile's pinned certificate, if any. On an
    /// untrusted certificate (no pin yet, or a changed one) this prompts for
    /// explicit confirmation — mirroring the `ntwire` CLI's TOFU prompt —
    /// persists the pin only once the user agrees, and retries exactly once.
    private func performAuthentication(privateKey: Data, passphrase: String?, wireGuardKey: Data) async throws -> AuthenticationResponse {
        do {
            return try await attemptAuthenticateSSH(pin: profile.certificatePin, privateKey: privateKey, passphrase: passphrase, wireGuardKey: wireGuardKey)
        } catch let untrusted as UntrustedServerCertificateError {
            guard await confirmTrust(untrusted) else { throw untrusted }
            var pinned = profile
            pinned.certificatePin = untrusted.presentedPin
            onUpdate(pinned)
            return try await attemptAuthenticateSSH(pin: untrusted.presentedPin, privateKey: privateKey, passphrase: passphrase, wireGuardKey: wireGuardKey)
        }
    }

    private func attemptAuthenticateSSH(pin: String?, privateKey: Data, passphrase: String?, wireGuardKey: Data) async throws -> AuthenticationResponse {
        let untrusted = UntrustedCertBox()
        let challenges = ChallengeLog()
        let transport = URLSessionTransport(pin: pin, onUntrustedCertificate: untrusted.set, onChallenge: challenges.record)
        let api = try NtwireControlAPI(serverURL: profile.serverURL, transport: transport)
        do {
            return try await api.authenticateSSH(privateKey: privateKey, passphrase: passphrase, wireGuardPrivateKey: wireGuardKey)
        } catch {
            if let untrusted = untrusted.value { throw untrusted }
            throw DiagnosableTransportError(underlying: error, challengeCount: challenges.count, lastAccepted: challenges.lastAccepted)
        }
    }

    private func confirmTrust(_ error: UntrustedServerCertificateError) async -> Bool {
        await withCheckedContinuation { continuation in
            pendingTrust = PendingTrust(error: error, continuation: continuation)
        }
    }

    /// A minimal GET, isolated from SSH auth entirely, so a failure here
    /// tells us whether the problem is the TLS/pinning layer itself or
    /// something specific to the POST /v1/auth request that follows it.
    private func probeServerInfo() {
        probing = true
        probeResult = nil
        Task {
            defer { probing = false }
            let untrusted = UntrustedCertBox()
            let challenges = ChallengeLog()
            let transport = URLSessionTransport(pin: profile.certificatePin, onUntrustedCertificate: untrusted.set, onChallenge: challenges.record)
            do {
                let api = try NtwireControlAPI(serverURL: profile.serverURL, transport: transport)
                let info = try await api.serverInfo()
                probeResult = "OK: server version \(info.version), capabilities \(info.capabilities.joined(separator: ", "))"
            } catch {
                if let untrusted = untrusted.value {
                    probeResult = "FAILED: \(untrusted.errorDescription ?? "untrusted certificate")"
                } else {
                    probeResult = "FAILED: \(DiagnosableTransportError(underlying: error, challengeCount: challenges.count, lastAccepted: challenges.lastAccepted).errorDescription ?? error.localizedDescription)"
                }
            }
        }
    }

    private func disconnect() {
        do { try credentialStore.remove(account: ProfileCredentialAccount.sessionToken(for: profile.id)) }
        catch { self.error = error.localizedDescription }
        result = nil
        connectionState = connectionState.applying(.disconnectRequested)
    }
}

private enum SSHKeyChange {
    case unchanged
    case replace(Data)
    case remove
}

private struct ProfileEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State private var displayName: String
    @State private var server: String
    @State private var method: AuthenticationMethod
    @State private var error: String?
    @State private var keyChange: SSHKeyChange = .unchanged
    @State private var importingKey = false
    let profile: ServerProfile?
    let onSave: (ServerProfile, SSHKeyChange) -> Void

    init(profile: ServerProfile? = nil, onSave: @escaping (ServerProfile, SSHKeyChange) -> Void) {
        self.profile = profile
        self.onSave = onSave
        _displayName = State(initialValue: profile?.displayName ?? "")
        _server = State(initialValue: profile?.serverURL.absoluteString ?? "https://")
        _method = State(initialValue: profile?.authenticationMethod ?? .oidc)
    }

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
                if method == .ssh {
                    Section("SSH private key") {
                        Button("Import private key from Files…") { importingKey = true }
                        switch keyChange {
                        case .unchanged: Text(profile == nil ? "No key imported yet." : "Leave unchanged, or import a replacement.")
                        case .replace: Text("A replacement key is ready to save.")
                        case .remove: Text("The saved key will be removed.")
                        }
                        Button("Remove saved key", role: .destructive) { keyChange = .remove }
                            .disabled(profile == nil)
                    }
                }
                if let error {
                    Text(error).foregroundStyle(.red)
                }
            }
            .navigationTitle(profile == nil ? "Add server" : "Edit server")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                }
            }
        }
        .fileImporter(isPresented: $importingKey, allowedContentTypes: [.data, .text]) { result in
            do {
                let url = try result.get()
                guard url.startAccessingSecurityScopedResource() else { throw CocoaError(.fileReadNoPermission) }
                defer { url.stopAccessingSecurityScopedResource() }
                let key = try Data(contentsOf: url)
                guard !key.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
                keyChange = .replace(key)
            } catch {
                self.error = "Could not import SSH private key: \(error.localizedDescription)"
            }
        }
    }

    private func save() {
        guard let url = URL(string: server) else {
            error = "Enter a valid HTTPS URL."
            return
        }
        do {
            let profile = try ServerProfile(id: profile?.id ?? UUID(), displayName: displayName, serverURL: url, authenticationMethod: method)
            onSave(profile, keyChange)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
