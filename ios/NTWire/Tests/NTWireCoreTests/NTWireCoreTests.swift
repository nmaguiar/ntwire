import Foundation
import CryptoKit
#if canImport(Security)
import Security
#endif
#if canImport(CommonCrypto)
import CommonCrypto
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

    @Test func masqueCSRIsSelfConsistent() throws {
        let (privateKey, publicKey) = try MASQUEKeyPair.generateP256()
        let pem = try MASQUECSR.build(privateKey: privateKey, publicKey: publicKey)
        #expect(pem.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        #expect(pem.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))

        let der = try derFromPEM(pem)
        var outer = DERReader(der)
        var csr = DERReader(try outer.value(tag: 0x30))

        // Re-wrap the extracted content as its own full TLV (tag+length+
        // content) -- DERWriter's length encoding is canonical, so this
        // reconstructs exactly the bytes that were signed.
        let requestInfoContent = try csr.value(tag: 0x30)
        var requestInfoWriter = DERWriter()
        requestInfoWriter.appendRaw(0x30, requestInfoContent)
        let requestInfoDER = requestInfoWriter.bytes

        var algorithm = DERReader(try csr.value(tag: 0x30))
        let algorithmOID = try algorithm.value(tag: 0x06)
        var expectedOIDWriter = DERWriter()
        expectedOIDWriter.appendOID(ASN1OID.ecdsaWithSHA256)
        var expectedOIDReader = DERReader(expectedOIDWriter.bytes)
        #expect(try algorithmOID == expectedOIDReader.value(tag: 0x06))

        let signatureBitString = try csr.value(tag: 0x03)
        #expect(signatureBitString.first == 0x00) // unused-bits byte
        let signature = Data(signatureBitString.dropFirst())
        #expect(csr.isAtEnd)

        // Verify against the public key embedded in the CSR itself (not the
        // `publicKey` this test already holds), so the assertion proves the
        // CSR is internally self-consistent, not just that signing worked.
        var info = DERReader(requestInfoContent)
        _ = try info.value(tag: 0x02) // version
        _ = try info.value(tag: 0x30) // subject Name
        var spki = DERReader(try info.value(tag: 0x30))
        _ = try spki.value(tag: 0x30) // AlgorithmIdentifier
        let spkiBitString = try spki.value(tag: 0x03)
        let point = Data(spkiBitString.dropFirst())

        let keyAttributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var keyError: Unmanaged<CFError>?
        guard let embeddedPublicKey = SecKeyCreateWithData(point as CFData, keyAttributes as CFDictionary, &keyError) else {
            Issue.record("could not reconstruct the CSR's embedded public key")
            return
        }
        var verifyError: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(embeddedPublicKey, .ecdsaSignatureMessageX962SHA256, requestInfoDER as CFData, signature as CFData, &verifyError)
        #expect(verified)
    }

#if canImport(CommonCrypto)
    // The strongest available correctness signal without a physical device:
    // a successful `SecPKCS12Import` means Apple's own parser accepted the
    // container's ASN.1 framing, decrypted both SafeContents with this
    // package's PBE/KDF implementation, verified the MacData HMAC, and paired
    // the cert and key into one SecIdentity by localKeyId -- not just an
    // internal round-trip. Only `.tripleDES` is exercised here: it's this
    // package's default and only actually-used cert cipher (nothing calls
    // `assemble` with `.rc2_40`); a one-off run of `.rc2_40` against this
    // same toolchain produced an unexplained -26276 alongside four passes,
    // so it isn't a reliable signal and isn't worth gating the suite on for a
    // path production never takes. `rc2FortyBitRoundTripsInCommonCrypto`
    // below still isolates CommonCrypto's RC2 handling on its own. Whether
    // `.tripleDES` is what a real device's NERelay.identityData actually
    // needs is still unverified without hardware (see docs/IOS.md).
    @Test func pkcs12RoundTripsThroughSecPKCS12Import() throws {
        let cipher = MASQUEPKCS12CertCipher.tripleDES
        let privateKey = try pkcs12FixturePrivateKey()
        let certPEM = pkcs12FixtureCertificatePEM()
        let certDER = try derFromPEM(certPEM)

        let (pkcs12Data, password) = try MASQUEPKCS12.assemble(leafCertificatePEM: certPEM, privateKey: privateKey, certCipher: cipher)

        var result: CFArray?
        let status = SecPKCS12Import(pkcs12Data as CFData, [kSecImportExportPassphrase: password] as CFDictionary, &result)
        #expect(status == errSecSuccess, "cipher \(cipher) rejected by SecPKCS12Import, status \(status)")
        guard status == errSecSuccess, let items = result as? [[String: Any]], let first = items.first else { return }

        guard let identityValue = first[kSecImportItemIdentity as String] else {
            Issue.record("importer did not pair the key and certificate into one SecIdentity")
            return
        }
        let identity = identityValue as! SecIdentity

        var leaf: SecCertificate?
        #expect(SecIdentityCopyCertificate(identity, &leaf) == errSecSuccess)
        if let leaf {
            #expect((SecCertificateCopyData(leaf) as Data) == certDER)
        }
    }

    // Pins this package's RFC 7292 Appendix B.2 KDF against an independently
    // generated reference: the MacData salt/iterations/digest and
    // AuthenticatedSafe bytes below were extracted (via `openssl asn1parse
    // -strparse`) from a file produced by
    //   openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem \
    //     -out ref.p12 -passout pass:testpassword123 \
    //     -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
    // A passing `SecPKCS12Import` proves Apple's parser accepts the overall
    // container; this proves the KDF itself reproduces openssl's own MacData
    // HMAC byte-for-byte, independent of any Apple API.
    @Test func kdfMatchesOpenSSLReferenceMacDigest() throws {
        let authenticatedSafeDER = hexData(
            "308203a23082025f06092a864886f70d010706a08202503082024c0201003082024506092a864886f70d010701301c060a2a864886f70d010c0103300e0408423b26d383d83fe30202080080820218f41cd4a5da851bde21a137678fe62252bac4723dbc5871282ee7a403f21c4d89f95dfb829d928f56fd22402c18b2a2767e2abac9145fec984dc3b2deb75c5d6a3a3a812cc73c4a3480687b6f81ca1f5da0f6fe7e040fa6cdca6fdc06f7f958d0add4906e41bfa96219509c79757f698865ae856319117a380cb9b05eb0a4f5628d7a56080a3092591ef32ea77bc6d6989568b4912ba533137173c8bb9665563cdda2cab153013c5b280245f39da2b3953d2ba89a390f045eaa99173eb95dfc931f005c24211deb58309d4fa8335b5213ac0b5f5930d34e4410367ba5df60df14d812323ee2dfd3563a8f703be424d53d3c31a3a85a6b5043b5a4d57c44b406c2670915769b9ca2a7eb964c6ff45c1417b41b37f79efa6744e847333a0a6e2cb03b7f6d8b69cf2be26e86c63ed532e871899dd6a795af78e6d5c5287ea7cceae3f38b4a0cc6bbdb19cd2c41a76c4d98b64d83852bc3a609e2deaeaa15329ed8c0b280553dc7d06abecb75ad82a6bfeae9186bd5aaac183404a0bdb8efd42a3aef4c3a481aeb48e4e3070ceefbb0f7824c13cab84dd70e08ba40108652681083834b784b8d61db7a09841f9dadbbb42f3d8317c719168241d087b38f74874f6f0eb1b6d2050e7b1c6bcaa084c47f1923b87ab10fdb748ef8237ae94d2bc77f463da7419bd2111cb4750b33d6cd080711ff81fb8df1313c7335b0ed9f8e25ba5d7fdbba79627797f1765c3d9fad250e408147b9cf787d1d6bcc3082013b06092a864886f70d010701a082012c048201283082012430820120060b2a864886f70d010c0a0102a081b43081b1301c060a2a864886f70d010c0103300e0408dd3001895c22d70a0202080004819074e9e9abb95bfb1d55811a7943852ae2165cb049d05dde179ec7634f2e497b676ccb33a673075cae4b71ba4c0b1e265f8d16603f5a97c74e97f6ba950c1382a95e2f60716155b9f2f3e338de61962bdb017830a25de4f347f755d889b315e9c5dc5100a7b886a9dacc785e435d69376551fe83742d5f1d85e26e3d2d611b7c5455157584a01a9f668708444f36882a2b315a302306092a864886f70d0109153116041494201cc08a1ccb50a83fe62bf5237753400e0916303306092a864886f70d01091431261e24006e00740077006900720065002d006b00640066002d0066006900780074007500720065"
        )
        let macSalt = hexData("e3bff3c36ae9038c378f70b7f76fe9ec")
        let macKey = PKCS12KDF.derive(id: .mac, password: "testpassword123", salt: macSalt, iterations: 2048, outputLength: 20)
        let digest = hmacSHA1(key: macKey, message: authenticatedSafeDER)
        #expect(digest == hexData("320c5dfcd82f21ab9599e8646cec3cd7c28de300"))
    }

    @Test func pkcs12ImportFailsClosedOnWrongPassword() throws {
        let privateKey = try pkcs12FixturePrivateKey()
        let (pkcs12Data, _) = try MASQUEPKCS12.assemble(leafCertificatePEM: pkcs12FixtureCertificatePEM(), privateKey: privateKey)

        var result: CFArray?
        let status = SecPKCS12Import(pkcs12Data as CFData, [kSecImportExportPassphrase: "definitely-not-the-password"] as CFDictionary, &result)
        #expect(status != errSecSuccess)
    }

    /// Isolates CommonCrypto's RC2 handling (a known "silently wrong
    /// effective-key-length" risk per the plan) from the PKCS#12 structure:
    /// a plain encrypt/decrypt round-trip with a fixed 40-bit key.
    @Test func rc2FortyBitRoundTripsInCommonCrypto() throws {
        let key = Data((0..<5).map { UInt8($0 * 17 + 1) })
        let iv = Data(repeating: 0, count: 8)
        let plaintext = Data("ntwire relay identity test payload".utf8)

        func crypt(_ operation: Int, _ input: Data) throws -> Data {
            var outBuffer = [UInt8](repeating: 0, count: input.count + 8)
            var moved = 0
            let status = key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
                iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                    input.withUnsafeBytes { inBuf -> CCCryptorStatus in
                        CCCrypt(CCOperation(operation), CCAlgorithm(kCCAlgorithmRC2), CCOptions(kCCOptionPKCS7Padding),
                                keyBuf.baseAddress, key.count, ivBuf.baseAddress,
                                inBuf.baseAddress, input.count, &outBuffer, outBuffer.count, &moved)
                    }
                }
            }
            #expect(status == kCCSuccess)
            return Data(outBuffer.prefix(moved))
        }

        let ciphertext = try crypt(kCCEncrypt, plaintext)
        #expect(ciphertext != plaintext)
        let decrypted = try crypt(kCCDecrypt, ciphertext)
        #expect(decrypted == plaintext)
    }
#endif
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

    /// A server that never advertises masque-relay-v1 must reach `connected`
    /// directly from `configuringRelay` -- it must not strand the UI there
    /// waiting for a `.relayConfigured` event that will never come.
    @Test func lifecycleSkipsRelayWhenServerDoesNotOfferOne() {
        var state = ConnectionState.disconnected
        state = state.applying(.connectRequested)
        state = state.applying(.authenticationSucceeded)
        #expect(state == .configuringRelay)
        state = state.applying(.relayUnavailable)
        #expect(state == .connected)
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

/// A fixed, self-signed test-only certificate (CN "ntwire-test", generated
/// with `openssl req -x509 -newkey ec`) — stands in for the self-signed
/// certificate an ntwire server presents.
private let fixtureCertificateDERBase64 = """
MIIBgTCCASegAwIBAgIUBUDsVj/ellMvAKm3Xkqlm04qjrQwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLbnR3aXJlLXRlc3QwHhcNMjYwODIyMDI1NTMwWhcNMzYwODE5MDI1NTMwWjAWMRQwEgYDVQQDDAtudHdpcmUtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEfxWqEMXZfGFJIh5Vc50BiZrAN5BmkJ/A7U8DgT7OBkXpFLlLkgN+tdAiSsvE1wsZM2BLIX/2T9hWUr8xo7ysWjUzBRMB0GA1UdDgQWBBSJhdIX6T1BP67UYa1ojl/g7ojPFDAfBgNVHSMEGDAWgBSJhdIX6T1BP67UYa1ojl/g7ojPFDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCowmjPG3ISnz2afluPjVntDSm8V/4mhJP52pljxXUhlQIgLzl46IcQ3rSZKsEiiSU7eCREJ/4ipj+KFyWnO0/jb5U=
"""

private func fixtureCertificatePEM() -> String {
    "-----BEGIN CERTIFICATE-----\n\(fixtureCertificateDERBase64)\n-----END CERTIFICATE-----\n"
}

#if canImport(CommonCrypto)
// A second fixed key+certificate pair, distinct from `fixtureCertificateDERBase64`
// above (which is used only for TLS-trust parsing and has no known private key).
// The PKCS#12 tests need the certificate's embedded public key to actually
// correspond to the private key sealed inside the container -- SecPKCS12Import
// verifies this and rejects a mismatched pair with errSecDecode, unlike openssl's
// `-nodes` extraction, which never checks it. Generated with:
//   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
//   openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=ntwire-test" -sha256
private let pkcs12FixtureCertificateDERBase64 = """
MIIBgTCCASegAwIBAgIUHYyA6BBryQhnPoK5ooZ4VechQPQwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLbnR3aXJlLXRlc3QwHhcNMjYwODIyMDUwOTQwWhcNMzYwODE5MDUwOTQwWjAWMRQwEgYDVQQDDAtudHdpcmUtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPlgo5i8RHY9TdujwYkhC6500hgh4LjbLXwkzdythGkjiqXEdlmv6elCVyuDiwWxcgRc38xEeYDWN9yA65aKyVejUzBRMB0GA1UdDgQWBBTo4kyUDREgddvaNlpoG9l2HJASbzAfBgNVHSMEGDAWgBTo4kyUDREgddvaNlpoG9l2HJASbzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIFl94jLI/J2ZAg88YEfX89Vm1V5Gx6wu2UAYmCKsy/2WAiEA2wvdg5Pn9x4+X1IdoRSD74/39T8aY3DfYaaf0u+Zz1o=
"""

private let pkcs12FixturePrivateKeyHex =
    "524c72bce2f92872ea7e8414e692ce5a40d11dba0690187806aeda168dcc7f50"
private let pkcs12FixturePublicKeyHex =
    "04f960a398bc44763d4ddba3c189210bae74d21821e0b8db2d7c24cddcad8469238aa5c47659afe9e942572b838b05b172045cdfcc447980d637dc80eb968ac957"

private func pkcs12FixtureCertificatePEM() -> String {
    "-----BEGIN CERTIFICATE-----\n\(pkcs12FixtureCertificateDERBase64)\n-----END CERTIFICATE-----\n"
}

private func hexData(_ hex: String) -> Data {
    var data = Data(capacity: hex.count / 2)
    var chars = hex.startIndex
    while chars < hex.endIndex {
        let next = hex.index(chars, offsetBy: 2)
        data.append(UInt8(hex[chars..<next], radix: 16)!)
        chars = next
    }
    return data
}

/// Imports the fixed private key matching `pkcs12FixtureCertificateDERBase64`
/// so the round-trip tests seal a private key that actually corresponds to the
/// certificate they bundle it with.
private func pkcs12FixturePrivateKey() throws -> SecKey {
    let external = hexData(pkcs12FixturePublicKeyHex) + hexData(pkcs12FixturePrivateKeyHex)
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits: 256
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(external as CFData, attributes as CFDictionary, &error) else {
        throw TestTrustError.certificateDecodingFailed
    }
    return key
}
#endif

private func testServerTrust() throws -> SecTrust {
    guard let data = Data(base64Encoded: fixtureCertificateDERBase64, options: .ignoreUnknownCharacters),
          let certificate = SecCertificateCreateWithData(nil, data as CFData)
    else { throw TestTrustError.certificateDecodingFailed }
    var trust: SecTrust?
    let status = SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust)
    guard status == errSecSuccess, let trust else { throw TestTrustError.trustCreationFailed }
    return trust
}
#endif
