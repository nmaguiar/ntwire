import Foundation

/// A platform-neutral description of the only relay configuration ntwire may
/// create. The iOS adapter will translate this into NERelayManager once the
/// server advertises the optional masque-relay-v1 capability.
public struct RelayConfiguration: Equatable, Sendable {
    public let gatewayURL: URL
    public let matchDomains: [String]
    public let excludedDomains: [String]
    public let selectedGrantNames: Set<String>

    public init(gatewayURL: URL, matchDomains: [String], excludedDomains: [String] = [], selectedGrantNames: Set<String>) throws {
        try ServerURL.validate(gatewayURL)
        let normalizedMatches = try Self.normalizeDomains(matchDomains)
        let normalizedExclusions = try Self.normalizeDomains(excludedDomains)
        guard !normalizedMatches.isEmpty else { throw RelayConfigurationError.emptyMatchDomains }
        self.gatewayURL = gatewayURL
        self.matchDomains = normalizedMatches
        self.excludedDomains = normalizedExclusions
        self.selectedGrantNames = selectedGrantNames
    }

    private static func normalizeDomains(_ domains: [String]) throws -> [String] {
        let values = try domains.map { raw -> String in
            let value = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, !value.contains("/"), !value.contains(":"), !value.contains(" "), value.split(separator: ".").count >= 2 else {
                throw RelayConfigurationError.invalidDomain(raw)
            }
            return value
        }
        return Array(Set(values)).sorted()
    }
}

public enum RelayConfigurationError: Error, Equatable, LocalizedError, Sendable {
    case emptyMatchDomains
    case invalidDomain(String)

    public var errorDescription: String? {
        switch self {
        case .emptyMatchDomains: return "Network Relay requires explicit private match domains."
        case let .invalidDomain(value): return "Invalid relay domain: \(value)"
        }
    }
}

public enum ConnectionEvent: Equatable, Sendable {
    case connectRequested
    case authenticationSucceeded
    case relayConfigured
    case relayUnavailable
    case transportConnected
    case transportLost
    case credentialsExpired
    case disconnectRequested
    case failed(String)
}

public enum ConnectionState: Equatable, Sendable {
    case disconnected
    case authenticating
    case configuringRelay
    case connecting
    case connected
    case reconnecting
    case loginRequired
    case failed(String)

    public func applying(_ event: ConnectionEvent) -> ConnectionState {
        switch (self, event) {
        case (_, .disconnectRequested): return .disconnected
        case (_, .credentialsExpired): return .loginRequired
        case (_, let .failed(message)): return .failed(message)
        case (.disconnected, .connectRequested), (.loginRequired, .connectRequested), (.failed, .connectRequested): return .authenticating
        case (.authenticating, .authenticationSucceeded): return .configuringRelay
        case (.configuringRelay, .relayConfigured): return .connecting
        case (.configuringRelay, .relayUnavailable): return .connected
        case (.connecting, .transportConnected), (.reconnecting, .transportConnected): return .connected
        case (.connected, .transportLost): return .reconnecting
        default: return self
        }
    }
}
