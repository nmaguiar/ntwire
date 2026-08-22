import Foundation
import CryptoKit
#if canImport(Security)
import Security
#endif
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

    @Test func createsSignedSSHSessionRequest() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let pkcs8 = Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]) + key.rawRepresentation
        let pem = Data("-----BEGIN PRIVATE KEY-----\n\(pkcs8.base64EncodedString())\n-----END PRIVATE KEY-----\n".utf8)
        let payload = Data("{\"session_id\":\"session\",\"token\":\"secret\",\"ttl_seconds\":900,\"method\":\"ssh\"}".utf8)
        let api = try NtwireControlAPI(serverURL: URL(string: "https://vpn.example")!, transport: StubTransport(data: payload, statusCode: 200, expectedPath: "/v1/auth", expectedMethod: "POST"))
        let response = try await api.authenticateSSH(privateKey: pem, wireGuardPrivateKey: WireGuardIdentity.makePrivateKey())
        #expect(response.sessionID == "session")
        #expect(response.method == "ssh")
    }

    @Test func detectsEncryptedSSHKeyBeforeAttemptingAuthentication() {
        let key = Data("-----BEGIN ENCRYPTED PRIVATE KEY-----\nignored\n-----END ENCRYPTED PRIVATE KEY-----".utf8)
        #expect(SSHPrivateKey.requiresPassphrase(key))
        #expect(throws: SSHAuthenticationError.passphraseRequired) {
            _ = try SSHPrivateKey.signer(from: key)
        }
    }

    @Test func importsAndSignsWithECDSAP256PKCS8Key() throws {
        let pem = Data("""
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL6p0lyfTKs49MKzf
        9VuZdpmYOrTS8P8rXQqJ03YL0zGhRANCAAQZeHsr4t+n11pg2SEsK48jdKHpSe9S
        OJSX6xRLXE4PXo0nGDZ2ndaRgK3Zb8rY82uEPsol9ybKJLpI2EYcUPgP
        -----END PRIVATE KEY-----
        """.utf8)
        let signer = try SSHPrivateKey.signer(from: pem)
        #expect(SSHPrivateKey.authorizedKey(for: signer).hasPrefix("ecdsa-sha2-nistp256 "))
        let blob = try signedBlob(SSHPrivateKey.signature(Data("ntwire".utf8), with: signer))
        #expect(blob.algorithm == "ecdsa-sha2-nistp256")
        let (r, remaining) = try sshReadField(blob.payload)
        let (s, trailing) = try sshReadField(remaining)
        #expect(!r.isEmpty && !s.isEmpty && trailing.isEmpty)
    }

#if canImport(Security)
    @Test func importsAndSignsWithRSAPKCS8Key() throws {
        let pem = Data("""
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7KqvlWI0/szyH
        gPyXllXxaEWsbYDT9Iw89TxJja/zXjuOeNiDUqaq2XTJCUQbtY3wCDbLCilaa6xm
        ggJakSx0rY0ljrJqMvYjDbJSF8qkv2vInkj29w+uXAeJh+6uueUfiWqkjfMGqX0k
        tGlmZiWk8a2ZR5IAfhorZBLkyA4f4Kqb3R2SEsxJ/lag+bU6QlIrgf91ZXjI4I9g
        4qFVj1XbqJa89RW3S+EiDqEIY76kD79UnhFJ1/5tzwDAIgkxTDHDkRu6Octo20gu
        5/N+e7qsmT9vrrd3ENp+RgU/HIxiCz/xUdaJWTrxavZo+/4qzCD+YvdJMjGUxdAh
        V4AeKg1pAgMBAAECgf8gho/xI5n6k1kG0cIHZQmETs5fH3e0mrufn1PFaErAwDro
        kItxOqvCI3vh+e4P4qrXGvfYY0on3T8VeOoCFjJRRTk4+1ltmyqGbPA97EwjTxR1
        JyUG6ozwmFzbhpYhqKBEDo4bTagh6uqy8y1RrXS+yqKID9Khz3j/zlUMf0ncs9LH
        nJngrrq7NL4ZxVexTfwqCd30GjowidUt7qU2iaVkZr2cAeQ5A0L1jFg2qo5EerzB
        bfHnnNc29BZVtQosPwBosbVxjmnovKFXtIZ/M4nObzUlvcGH0dTQLukN2dSrv2XL
        aBWuUPJPQ9OUAjLheUtAFVhh+mhulsPIwrn3vLUCgYEA6pNQ0SXYxq8eS1mpjRqd
        fXmXnyyRXWYQpRtNefttwKEgCFzz3Rma0NXtfVP2WHGxy1vocmK17FzErv/pwipv
        k3RgOV0MdOKbV0oFPe9Bxj7t3nHJqAmJAFUKIrD6X2kmkEXQYW7OeKxF7qZ8S9fS
        RZZhM6m/K4vWw/ERL75jLs0CgYEAzELgSQ8BKe25w4CkZqwwhC0n6zAjJdSk5ysw
        6a9BkCbfwEC1p+mqcNgmhBdI+yngJtG61nRmU7pnDJ2TOCqwUezs74vPawAkljeO
        3cX1URH2YQAbddptlolUfjNwCt5pHxa+x0jfhMhqMJm6l6CxvpPwXLgZdc19gAFo
        kr35YQ0CgYEA3eMLh0rtisMLPOtLXpXWc2IY8hAOUPLCu+rflosmfhfrXP3QD0yx
        DOnPA8XwOCkTrPD7J3gH7dSyl3arf2b0s95ZRumlZssTdbYmzzcKWKQeDVRFFBYw
        6YeHVtlhe+7S85WWTxOpaqxKWjxRRsyXsgtVVrEyi9ZzCFV3lFnbJ+ECgYEAwqvK
        DlcaiNdkgAsOpDvfUVmn/eI23Us4joj/aPf6yGQEQ7poZsuwATRAIQwAJj/WvaiN
        JO5yx8GTjNZxBMrKmInxlqvs1tGgDPqOUpbkIou4AOKVSVEPuLTRriVf1zv5fAO1
        d0DgpjBL5F3fE7u3KybbocJjoX5i6aht/czI69ECgYASUAhZ77mHhQI6jR4HTjDV
        54VwFYQoXzZhQ/lg4xy8Pk78pbzF2r4WNrD9I/sTPQIXq4msSOI2YqS6hhUlAUK7
        TJPV2JxUO2I3n+7HhbdfHIIqJQiqZNzFPw18zrfJbT/+hlcSvrCQQ6zjgyJAOyCP
        CJUweDUnyHOOr0vRn8EOEw==
        -----END PRIVATE KEY-----
        """.utf8)
        let signer = try SSHPrivateKey.signer(from: pem)
        #expect(SSHPrivateKey.authorizedKey(for: signer).hasPrefix("ssh-rsa "))
        let blob = try signedBlob(SSHPrivateKey.signature(Data("ntwire".utf8), with: signer))
        #expect(blob.algorithm == "ssh-rsa")
        #expect(blob.payload.count == 256)
    }
#endif

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

    @Test func persistsProfileEditsAndDeletions() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        let file = directory.appendingPathComponent("profiles.json")
        let first = try ServerProfile(displayName: "Work", serverURL: URL(string: "https://work.example")!)
        let second = try ServerProfile(displayName: "Lab", serverURL: URL(string: "https://lab.example")!)
        let store = JSONProfileStore(fileURL: file)
        try store.save([first, second])

        var edited = first
        edited.displayName = "Work VPN"
        try store.save([edited])
        #expect(try store.load() == [edited])
        try FileManager.default.removeItem(at: directory)
    }

    @Test func credentialTestDoubleClearsValue() throws {
        let store = InMemoryCredentialStore()
        try store.write(Data("refresh-token".utf8), account: "https://vpn.example/issuer")
        #expect(try store.read(account: "https://vpn.example/issuer") == Data("refresh-token".utf8))
        try store.remove(account: "https://vpn.example/issuer")
        #expect(try store.read(account: "https://vpn.example/issuer") == nil)
    }

    @Test func SSHKeyAccountIsUniqueToProfileAndContainsNoKeyMaterial() throws {
        let one = UUID()
        let two = UUID()
        let first = ProfileCredentialAccount.sshPrivateKey(for: one)
        #expect(first != ProfileCredentialAccount.sshPrivateKey(for: two))
        #expect(first.contains(one.uuidString))
        #expect(!first.contains("PRIVATE KEY"))
    }

    @Test func relayConfigurationRequiresPrivateMatches() throws {
        let config = try RelayConfiguration(gatewayURL: URL(string: "https://relay.example")!, matchDomains: ["Db.Internal.Example", "db.internal.example"], excludedDomains: ["public.db.internal.example"], selectedGrantNames: ["db"])
        #expect(config.matchDomains == ["db.internal.example"])
        #expect(config.excludedDomains == ["public.db.internal.example"])
        #expect(throws: RelayConfigurationError.emptyMatchDomains) {
            try RelayConfiguration(gatewayURL: URL(string: "https://relay.example")!, matchDomains: [], selectedGrantNames: [])
        }
    }

    @Test func certificateFingerprintMatchesServerFormat() throws {
        // Golden vector cross-checked independently against the server's
        // "SHA256:" + base64.RawStdEncoding format (pkg/server/tls.go
        // TLSManager.Fingerprint): `printf 'test' | openssl dgst -sha256
        // -binary | openssl base64 -A` with the trailing '=' stripped.
        let pin = CertificateFingerprint.sha256Pin(for: Data("test".utf8))
        #expect(pin == "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg")
    }

    @Test func certificateFingerprintDiffersForDifferentCertificates() throws {
        let first = CertificateFingerprint.sha256Pin(for: Data("cert-a".utf8))
        let second = CertificateFingerprint.sha256Pin(for: Data("cert-b".utf8))
        #expect(first != second)
        #expect(!first.contains("="))
    }

#if canImport(Security)
    @Test func pinningDelegateRejectsAnUnknownCertificateOnFirstConnectInsteadOfAutoTrusting() throws {
        let trust = try testServerTrust()
        let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let expectedPin = CertificateFingerprint.sha256Pin(for: SecCertificateCopyData(certificate!) as Data)

        let reported = TestUntrustedBox()
        let tofu = PinningURLSessionDelegate(expectedPin: nil, onUntrustedCertificate: reported.set)
        let (disposition, credential) = tofu.evaluate(trust)
        #expect(disposition == .cancelAuthenticationChallenge)
        #expect(credential == nil)
        #expect(reported.value == UntrustedServerCertificateError(presentedPin: expectedPin, previousPin: nil))
    }

    @Test func pinningDelegateAcceptsACertificateMatchingTheStoredPin() throws {
        let trust = try testServerTrust()
        let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let expectedPin = CertificateFingerprint.sha256Pin(for: SecCertificateCopyData(certificate!) as Data)

        let pinned = PinningURLSessionDelegate(expectedPin: expectedPin)
        let (disposition, credential) = pinned.evaluate(trust)
        #expect(disposition == .useCredential)
        #expect(credential != nil)
    }

    @Test func pinningDelegateRejectsCertificateThatDoesNotMatchStoredPin() throws {
        let trust = try testServerTrust()
        let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let presentedPin = CertificateFingerprint.sha256Pin(for: SecCertificateCopyData(certificate!) as Data)

        let reported = TestUntrustedBox()
        let mismatched = PinningURLSessionDelegate(expectedPin: "SHA256:not-the-real-pin", onUntrustedCertificate: reported.set)
        let (disposition, credential) = mismatched.evaluate(trust)
        #expect(disposition == .cancelAuthenticationChallenge)
        #expect(credential == nil)
        #expect(reported.value == UntrustedServerCertificateError(presentedPin: presentedPin, previousPin: "SHA256:not-the-real-pin"))
    }
#endif

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

private func signedBlob(_ encoded: String) throws -> (algorithm: String, payload: Data) {
    guard let data = Data(base64Encoded: encoded) else { throw SSHAuthenticationError.malformedPrivateKey }
    let (algorithm, afterAlgorithm) = try sshReadField(data)
    let (payload, remainder) = try sshReadField(afterAlgorithm)
    #expect(remainder.isEmpty)
    return (String(decoding: algorithm, as: UTF8.self), payload)
}

private func sshReadField(_ data: Data) throws -> (Data, Data) {
    guard data.count >= 4 else { throw SSHAuthenticationError.malformedPrivateKey }
    let count = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
    guard data.count >= 4 + count else { throw SSHAuthenticationError.malformedPrivateKey }
    return (Data(data[4..<(4 + count)]), Data(data.dropFirst(4 + count)))
}

#if canImport(Security)
private final class TestUntrustedBox: @unchecked Sendable {
    private(set) var value: UntrustedServerCertificateError?
    func set(_ error: UntrustedServerCertificateError) { value = error }
}

private enum TestTrustError: Error { case certificateDecodingFailed, trustCreationFailed }

/// A `SecTrust` wrapping a fixed, self-signed test-only certificate (CN
/// "ntwire-test", generated with `openssl req -x509 -newkey ec`) — stands in
/// for the self-signed certificate an ntwire server presents.
private func testServerTrust() throws -> SecTrust {
    let der = """
    MIIBgTCCASegAwIBAgIUBUDsVj/ellMvAKm3Xkqlm04qjrQwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLbnR3aXJlLXRlc3QwHhcNMjYwODIyMDI1NTMwWhcNMzYwODE5MDI1NTMwWjAWMRQwEgYDVQQDDAtudHdpcmUtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEfxWqEMXZfGFJIh5Vc50BiZrAN5BmkJ/A7U8DgT7OBkXpFLlLkgN+tdAiSsvE1wsZM2BLIX/2T9hWUr8xo7ysWjUzBRMB0GA1UdDgQWBBSJhdIX6T1BP67UYa1ojl/g7ojPFDAfBgNVHSMEGDAWgBSJhdIX6T1BP67UYa1ojl/g7ojPFDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCowmjPG3ISnz2afluPjVntDSm8V/4mhJP52pljxXUhlQIgLzl46IcQ3rSZKsEiiSU7eCREJ/4ipj+KFyWnO0/jb5U=
    """
    guard let data = Data(base64Encoded: der, options: .ignoreUnknownCharacters),
          let certificate = SecCertificateCreateWithData(nil, data as CFData)
    else { throw TestTrustError.certificateDecodingFailed }
    var trust: SecTrust?
    let status = SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust)
    guard status == errSecSuccess, let trust else { throw TestTrustError.trustCreationFailed }
    return trust
}
#endif
