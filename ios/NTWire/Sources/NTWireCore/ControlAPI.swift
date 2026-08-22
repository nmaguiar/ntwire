import Foundation

public protocol NtwireHTTPTransport: Sendable {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: NtwireHTTPTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
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
}
