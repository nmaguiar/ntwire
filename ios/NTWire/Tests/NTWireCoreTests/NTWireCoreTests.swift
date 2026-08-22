import Foundation
import Testing
@testable import NTWireCore

struct NTWireCoreTests {
    private struct StubTransport: NtwireHTTPTransport {
        let data: Data
        let statusCode: Int
        let expectedPath: String
        let expectedMethod: String

        func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            #expect(request.url?.path == expectedPath)
            #expect(request.httpMethod == expectedMethod)
            let response = HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
            return (data, response)
        }
    }

    @Test func discoversServerInfoThroughInjectedTransport() async throws {
        let payload = Data("{\"version\":1,\"capabilities\":[\"tcp\"]}".utf8)
        let api = try NtwireControlAPI(serverURL: URL(string: "https://vpn.example")!, transport: StubTransport(data: payload, statusCode: 200, expectedPath: "/v1/info", expectedMethod: "GET"))
        let info = try await api.serverInfo()
        #expect(info.version == 1)
        #expect(info.capabilities == ["tcp"])
        #expect(info.oidcIssuers.isEmpty)
    }

    @Test func parsesOptionalMASQUEMetadataAndCertificateEnrollment() async throws {
        let infoPayload = Data("{\"version\":1,\"capabilities\":[\"tcp\",\"masque-relay-v1\"],\"masque\":{\"http2_url\":\"https://relay.example\",\"match_domains\":[\"db.private.example\"]}}".utf8)
        let infoAPI = try NtwireControlAPI(serverURL: URL(string: "https://vpn.example")!, transport: StubTransport(data: infoPayload, statusCode: 200, expectedPath: "/v1/info", expectedMethod: "GET"))
        let info = try await infoAPI.serverInfo()
        #expect(info.masque?.http2URL == URL(string: "https://relay.example"))
        #expect(info.masque?.matchDomains == ["db.private.example"])

        let responsePayload = Data("{\"certificate_pem\":\"cert\",\"issuer_pem\":\"issuer\",\"expires_at\":\"2026-08-21T12:00:00Z\"}".utf8)
        let certificateAPI = try NtwireControlAPI(serverURL: URL(string: "https://vpn.example")!, transport: StubTransport(data: responsePayload, statusCode: 200, expectedPath: "/v1/masque/certificate", expectedMethod: "POST"))
        let certificate = try await certificateAPI.masqueCertificate(csrPEM: "CSR", bearerToken: "session-token")
        #expect(certificate.certificatePEM == "cert")
        #expect(certificate.expiresAt == ISO8601DateFormatter().date(from: "2026-08-21T12:00:00Z"))
    }

    @Test func parsesServerAndGrantResponse() throws {
        let json = """
        {"session_id":"session","token":"secret","ttl_seconds":900,"identity":"alice@example.test","method":"oidc","server_name":"internal","tunnels":[{"name":"reports","description":"Reports","virtual_port":18080,"target_hint":"reports.internal:443"}]}
        """.data(using: .utf8)!
        let result = try JSONDecoder().decode(AuthenticationResponse.self, from: json)
        #expect(result.ttlSeconds == 900)
        #expect(result.tunnels == [TunnelGrant(name: "reports", description: "Reports", virtualPort: 18080, targetHint: "reports.internal:443")])
        #expect(result.token == "secret")
    }

    @Test(arguments: [
        ("http://server.example", ProfileValidationError.serverURLMustUseHTTPS),
        ("https:///missing-host", ProfileValidationError.serverURLMustHaveHost),
        ("https://alice:secret@server.example", ProfileValidationError.serverURLMustNotContainCredentials),
        ("https://server.example/path", ProfileValidationError.serverURLMustNotContainPath),
        ("https://server.example/?x=1", ProfileValidationError.serverURLMustNotContainQueryOrFragment)
    ]) func rejectsUnsafeServerURLs(value: String, expected: ProfileValidationError) {
        #expect(throws: expected) {
            try ServerURL.validate(URL(string: value)!)
        }
    }

    @Test func persistsProfilesWithoutCredentials() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        let file = directory.appendingPathComponent("profiles.json")
        let profile = try ServerProfile(displayName: "Work", serverURL: URL(string: "https://vpn.example")!)
        let store = JSONProfileStore(fileURL: file)
        try store.save([profile])
        #expect(try store.load() == [profile])
        try FileManager.default.removeItem(at: directory)
    }

    @Test func credentialTestDoubleClearsValue() throws {
        let store = InMemoryCredentialStore()
        try store.write(Data("refresh-token".utf8), account: "https://vpn.example/issuer")
        #expect(try store.read(account: "https://vpn.example/issuer") == Data("refresh-token".utf8))
        try store.remove(account: "https://vpn.example/issuer")
        #expect(try store.read(account: "https://vpn.example/issuer") == nil)
    }

    @Test func relayConfigurationRequiresPrivateMatches() throws {
        let config = try RelayConfiguration(gatewayURL: URL(string: "https://relay.example")!, matchDomains: ["Db.Internal.Example", "db.internal.example"], excludedDomains: ["public.db.internal.example"], selectedGrantNames: ["db"])
        #expect(config.matchDomains == ["db.internal.example"])
        #expect(config.excludedDomains == ["public.db.internal.example"])
        #expect(throws: RelayConfigurationError.emptyMatchDomains) {
            try RelayConfiguration(gatewayURL: URL(string: "https://relay.example")!, matchDomains: [], selectedGrantNames: [])
        }
    }

    @Test func lifecycleFailsClosedOnCredentialExpiry() {
        var state = ConnectionState.disconnected
        state = state.applying(.connectRequested)
        state = state.applying(.authenticationSucceeded)
        state = state.applying(.relayConfigured)
        state = state.applying(.transportConnected)
        #expect(state == .connected)
        #expect(state.applying(.credentialsExpired) == .loginRequired)
    }
}
