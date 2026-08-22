import Foundation

public protocol NtwireHTTPTransport: Sendable {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: NtwireHTTPTransport {
    private let session: URLSession
    private let ownsSession: Bool

    public init(session: URLSession = .shared) {
        self.session = session
        self.ownsSession = false
    }

    #if canImport(Security)
    /// Builds a session that pins the ntwire server's certificate instead of
    /// relying on system PKI trust, per the TOFU/pinning model in docs/IOS.md.
    /// Pass the profile's stored `certificatePin`, or `nil` if nothing is
    /// pinned yet. `onUntrustedCertificate` fires once, and the handshake is
    /// always cancelled, whenever the presented certificate doesn't exactly
    /// match `pin` — including when `pin` is `nil` — so the caller can prompt
    /// for explicit trust before retrying, rather than auto-accepting.
    public init(
        pin: String?,
        onUntrustedCertificate: (@Sendable (UntrustedServerCertificateError) -> Void)? = nil,
        onChallenge: (@Sendable (Int, Bool) -> Void)? = nil
    ) {
        let delegate = PinningURLSessionDelegate(expectedPin: pin, onUntrustedCertificate: onUntrustedCertificate, onChallenge: onChallenge)
        self.session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        self.ownsSession = true
    }
    #endif

    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        // A session built for one pinned connection (see the `pin:` init) is
        // never reused, so it must be invalidated here or its delegate leaks
        // for the life of the app; `.shared` must never be invalidated.
        defer { if ownsSession { session.finishTasksAndInvalidate() } }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw NtwireAPIError.nonHTTPResponse }
        return (data, http)
    }
}

public enum NtwireAPIError: Error, Equatable, Sendable {
    case nonHTTPResponse
    case unexpectedStatus(Int)
    case invalidEndpoint
}

public struct NtwireControlAPI<Transport: NtwireHTTPTransport>: Sendable {
    private let serverURL: URL
    private let transport: Transport
    private let decoder: JSONDecoder

    public init(serverURL: URL, transport: Transport) throws {
        try ServerURL.validate(serverURL)
        self.serverURL = serverURL
        self.transport = transport
        self.decoder = JSONDecoder()
    }

    public func serverInfo() async throws -> NtwireServerInfo {
        let request = try makeRequest(path: "/v1/info")
        let (data, response) = try await transport.data(for: request)
        guard (200 ..< 300).contains(response.statusCode) else { throw NtwireAPIError.unexpectedStatus(response.statusCode) }
        return try decoder.decode(NtwireServerInfo.self, from: data)
    }

    /// Creates an SSH-authenticated ntwire session. The passphrase is used
    /// only to unlock the supplied key for this request and is never retained.
    public func authenticateSSH(privateKey: Data, passphrase: String? = nil, wireGuardPrivateKey: Data, clientInfo: SSHClientInfo = SSHClientInfo()) async throws -> AuthenticationResponse {
        let signer = try SSHPrivateKey.signer(from: privateKey, passphrase: passphrase)
        let publicKey = SSHPrivateKey.authorizedKey(for: signer)
        let wireGuardPublicKey = try WireGuardIdentity.publicKey(privateKey: wireGuardPrivateKey)
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let nonce = randomNonce()
        let payload = SSHAuthenticationPayload.make(publicKey: publicKey, wireGuardPublicKey: wireGuardPublicKey, timestamp: timestamp, nonce: nonce, info: clientInfo)
        let signature = try SSHPrivateKey.signature(payload, with: signer)
        let requestBody = SSHAuthenticationRequest(publicKey: publicKey, wireGuardPublicKey: wireGuardPublicKey, timestamp: timestamp, nonce: nonce, info: clientInfo, signature: signature)
        var request = try makeRequest(path: "/v1/auth")
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(requestBody)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await transport.data(for: request)
        guard (200 ..< 300).contains(response.statusCode) else { throw NtwireAPIError.unexpectedStatus(response.statusCode) }
        return try decoder.decode(AuthenticationResponse.self, from: data)
    }

    /// Enrolls a locally generated public key with an enabled MASQUE server.
    /// The bearer token is used only for this HTTPS request and is never put
    /// into a Network Relay configuration or diagnostic surface.
    public func masqueCertificate(csrPEM: String, bearerToken: String) async throws -> MASQUECertificateResponse {
        guard !csrPEM.isEmpty, !bearerToken.isEmpty else { throw NtwireAPIError.invalidEndpoint }
        let body = try JSONEncoder().encode(MASQUECertificateRequest(csrPEM: csrPEM))
        var request = try makeRequest(path: "/v1/masque/certificate")
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await transport.data(for: request)
        guard (200 ..< 300).contains(response.statusCode) else { throw NtwireAPIError.unexpectedStatus(response.statusCode) }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(MASQUECertificateResponse.self, from: data)
    }

    private func makeRequest(path: String) throws -> URLRequest {
        guard var components = URLComponents(url: serverURL, resolvingAgainstBaseURL: false) else {
            throw NtwireAPIError.invalidEndpoint
        }
        components.path = path
        guard let url = components.url else { throw NtwireAPIError.invalidEndpoint }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    private func randomNonce() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return Data(bytes).base64URLEncodedString()
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
