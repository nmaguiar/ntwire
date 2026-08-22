import Foundation

public enum AuthenticationMethod: String, Codable, CaseIterable, Sendable {
    case oidc
    case ssh
}

public struct ServerProfile: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public var displayName: String
    public var serverURL: URL
    public var authenticationMethod: AuthenticationMethod
    public var oidcIssuerName: String?
    public var selectedGrantNames: Set<String>
    public var certificatePin: String?

    public init(
        id: UUID = UUID(),
        displayName: String,
        serverURL: URL,
        authenticationMethod: AuthenticationMethod = .oidc,
        oidcIssuerName: String? = nil,
        selectedGrantNames: Set<String> = [],
        certificatePin: String? = nil
    ) throws {
        try ServerURL.validate(serverURL)
        guard !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ProfileValidationError.emptyDisplayName
        }
        self.id = id
        self.displayName = displayName
        self.serverURL = serverURL
        self.authenticationMethod = authenticationMethod
        self.oidcIssuerName = oidcIssuerName
        self.selectedGrantNames = selectedGrantNames
        self.certificatePin = certificatePin
    }
}

public enum ProfileValidationError: Error, Equatable, LocalizedError, Sendable {
    case emptyDisplayName
    case serverURLMustUseHTTPS
    case serverURLMustHaveHost
    case serverURLMustNotContainCredentials
    case serverURLMustNotContainQueryOrFragment
    case serverURLMustNotContainPath

    public var errorDescription: String? {
        switch self {
        case .emptyDisplayName: return "A server profile needs a display name."
        case .serverURLMustUseHTTPS: return "The ntwire server URL must use HTTPS."
        case .serverURLMustHaveHost: return "The ntwire server URL must include a host."
        case .serverURLMustNotContainCredentials: return "The ntwire server URL must not include credentials."
        case .serverURLMustNotContainQueryOrFragment: return "The ntwire server URL must not include a query or fragment."
        case .serverURLMustNotContainPath: return "The ntwire server URL must not include a path."
        }
    }
}

public enum ServerURL {
    public static func validate(_ url: URL) throws {
        guard url.scheme?.lowercased() == "https" else { throw ProfileValidationError.serverURLMustUseHTTPS }
        guard url.host?.isEmpty == false else { throw ProfileValidationError.serverURLMustHaveHost }
        guard url.user == nil && url.password == nil else { throw ProfileValidationError.serverURLMustNotContainCredentials }
        guard url.query == nil && url.fragment == nil else { throw ProfileValidationError.serverURLMustNotContainQueryOrFragment }
        guard url.path.isEmpty || url.path == "/" else { throw ProfileValidationError.serverURLMustNotContainPath }
    }
}

public protocol ProfileStore: Sendable {
    func load() throws -> [ServerProfile]
    func save(_ profiles: [ServerProfile]) throws
}

/// Stable Keychain account names for credentials which must never be encoded
/// with a server profile. Keeping this mapping in the core package makes the
/// UI lifecycle testable without access to the iOS Keychain.
public enum ProfileCredentialAccount {
    public static func sshPrivateKey(for profileID: UUID) -> String {
        "profile/\(profileID.uuidString)/ssh-private-key"
    }

    public static func wireGuardPrivateKey(for profileID: UUID) -> String {
        "profile/\(profileID.uuidString)/wireguard-private-key"
    }

    public static func sessionToken(for profileID: UUID) -> String {
        "profile/\(profileID.uuidString)/session-token"
    }
}

public final class JSONProfileStore: ProfileStore, @unchecked Sendable {
    private let fileURL: URL
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(fileURL: URL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.decoder = JSONDecoder()
    }

    public func load() throws -> [ServerProfile] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        return try decoder.decode([ServerProfile].self, from: Data(contentsOf: fileURL))
    }

    public func save(_ profiles: [ServerProfile]) throws {
        try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(profiles).write(to: fileURL, options: [.atomic])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}
