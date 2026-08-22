import Foundation
import NetworkExtension

/// Gateway endpoints supplied only by the future masque-relay-v1 server
/// capability. At least one transport is required; ntwire never guesses a
/// gateway URL from its ordinary HTTPS control-plane address.
struct NetworkRelayEndpoints: Sendable {
    let http2: URL?
    let http3: URL?

    init(http2: URL? = nil, http3: URL? = nil) throws {
        guard http2 != nil || http3 != nil else { throw NetworkRelayControllerError.noEndpoint }
        for url in [http2, http3].compactMap({ $0 }) {
            try ServerURL.validate(url)
        }
        self.http2 = http2
        self.http3 = http3
    }
}

enum NetworkRelayControllerError: LocalizedError {
    case noEndpoint

    var errorDescription: String? {
        switch self {
        case .noEndpoint: return "The server did not provide a Network Relay gateway endpoint."
        }
    }
}

/// The app-owned Network Relay configuration boundary. This class deliberately
/// accepts no bearer token, refresh token, SSH key, or arbitrary header.
@MainActor
final class NetworkRelayController {
    private let manager: NERelayManager

    init(manager: NERelayManager = .shared()) {
        self.manager = manager
    }

    func install(
        displayName: String,
        endpoints: NetworkRelayEndpoints,
        configuration: RelayConfiguration
    ) async throws {
        try await load()
        let relay = NERelay()
        relay.http2RelayURL = endpoints.http2
        relay.http3RelayURL = endpoints.http3

        manager.localizedDescription = displayName
        manager.relays = [relay]
        // A nonempty allow-list is enforced by RelayConfiguration. Leaving
        // matchDomains unset would relay ordinary Internet traffic.
        manager.matchDomains = configuration.matchDomains
        manager.excludedDomains = configuration.excludedDomains.isEmpty ? nil : configuration.excludedDomains
        manager.isEnabled = true
        try await save()
    }

    func remove() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.removeFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    private func load() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }

    private func save() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }
}
