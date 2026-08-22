import Foundation

public struct NtwireServerInfo: Codable, Equatable, Sendable {
    public let version: Int
    public let capabilities: [String]
    public let requiredCapabilities: [String]
    public let oidcIssuers: [OIDCIssuer]
    /// Present only after the server has enabled an actual MASQUE relay.
    /// Its absence must not be treated as a failure by existing deployments.
    public let masque: MASQUERelayInfo?

    enum CodingKeys: String, CodingKey {
        case version, capabilities
        case requiredCapabilities = "required_capabilities"
        case oidcIssuers = "oidc_issuers"
        case masque
    }

    public init(version: Int, capabilities: [String], requiredCapabilities: [String] = [], oidcIssuers: [OIDCIssuer] = [], masque: MASQUERelayInfo? = nil) {
        self.version = version
        self.capabilities = capabilities
        self.requiredCapabilities = requiredCapabilities
        self.oidcIssuers = oidcIssuers
        self.masque = masque
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        capabilities = try values.decodeIfPresent([String].self, forKey: .capabilities) ?? []
        requiredCapabilities = try values.decodeIfPresent([String].self, forKey: .requiredCapabilities) ?? []
        oidcIssuers = try values.decodeIfPresent([OIDCIssuer].self, forKey: .oidcIssuers) ?? []
        masque = try values.decodeIfPresent(MASQUERelayInfo.self, forKey: .masque)
    }
}

/// Optional gateway metadata. URLs are server-supplied but must still be
/// validated before a Network Relay preference is installed.
public struct MASQUERelayInfo: Codable, Equatable, Sendable {
    public let http2URL: URL?
    public let http3URL: URL?
    public let matchDomains: [String]

    enum CodingKeys: String, CodingKey {
        case http2URL = "http2_url"
        case http3URL = "http3_url"
        case matchDomains = "match_domains"
    }

    public init(http2URL: URL? = nil, http3URL: URL? = nil, matchDomains: [String]) {
        self.http2URL = http2URL
        self.http3URL = http3URL
        self.matchDomains = matchDomains
    }
}

/// The certificate enrollment request carries a CSR only. It intentionally
/// cannot represent private-key bytes.
public struct MASQUECertificateRequest: Codable, Equatable, Sendable {
    public let csrPEM: String

    enum CodingKeys: String, CodingKey { case csrPEM = "csr_pem" }

    public init(csrPEM: String) { self.csrPEM = csrPEM }
}

/// Returned only through the authenticated ntwire control channel. Neither a
/// bearer token nor a private key appears in this response.
public struct MASQUECertificateResponse: Codable, Equatable, Sendable {
    public let certificatePEM: String
    public let issuerPEM: String
    public let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case certificatePEM = "certificate_pem"
        case issuerPEM = "issuer_pem"
        case expiresAt = "expires_at"
    }
}

public struct OIDCIssuer: Codable, Equatable, Identifiable, Sendable {
    public let name: String
    public let issuer: URL
    public let clientID: String
    public let scopes: [String]
    public let groupsClaim: String

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, issuer, scopes
        case clientID = "client_id"
        case groupsClaim = "groups_claim"
    }

    public init(name: String, issuer: URL, clientID: String, scopes: [String] = [], groupsClaim: String = "") {
        self.name = name
        self.issuer = issuer
        self.clientID = clientID
        self.scopes = scopes
        self.groupsClaim = groupsClaim
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        issuer = try values.decode(URL.self, forKey: .issuer)
        clientID = try values.decode(String.self, forKey: .clientID)
        scopes = try values.decodeIfPresent([String].self, forKey: .scopes) ?? []
        groupsClaim = try values.decodeIfPresent(String.self, forKey: .groupsClaim) ?? ""
    }
}

public struct TunnelGrant: Codable, Equatable, Identifiable, Sendable {
    public let name: String
    public let description: String
    public let virtualPort: Int
    public let targetHint: String
    public let instructions: String
    public let docsURL: URL?

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, description, instructions
        case virtualPort = "virtual_port"
        case targetHint = "target_hint"
        case docsURL = "docs_url"
    }

    public init(name: String, description: String = "", virtualPort: Int, targetHint: String = "", instructions: String = "", docsURL: URL? = nil) {
        self.name = name
        self.description = description
        self.virtualPort = virtualPort
        self.targetHint = targetHint
        self.instructions = instructions
        self.docsURL = docsURL
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        description = try values.decodeIfPresent(String.self, forKey: .description) ?? ""
        virtualPort = try values.decode(Int.self, forKey: .virtualPort)
        targetHint = try values.decodeIfPresent(String.self, forKey: .targetHint) ?? ""
        instructions = try values.decodeIfPresent(String.self, forKey: .instructions) ?? ""
        docsURL = try values.decodeIfPresent(URL.self, forKey: .docsURL)
    }
}

public struct AuthenticationResponse: Codable, Equatable, Sendable {
    public let sessionID: String
    public let token: String
    public let ttlSeconds: Int
    public let tunnels: [TunnelGrant]
    public let identity: String
    public let method: String
    public let serverName: String
    public let tunnelIP: String
    public let serverTunnelIP: String
    public let serverPublicKey: String

    enum CodingKeys: String, CodingKey {
        case tunnels, identity, method
        case sessionID = "session_id"
        case token
        case ttlSeconds = "ttl_seconds"
        case serverName = "server_name"
        case tunnelIP = "tunnel_ip"
        case serverTunnelIP = "server_tunnel_ip"
        case serverPublicKey = "server_public_key"
    }

    public init(sessionID: String = "", token: String = "", ttlSeconds: Int = 0, tunnels: [TunnelGrant] = [], identity: String = "", method: String = "", serverName: String = "", tunnelIP: String = "", serverTunnelIP: String = "", serverPublicKey: String = "") {
        self.sessionID = sessionID
        self.token = token
        self.ttlSeconds = ttlSeconds
        self.tunnels = tunnels
        self.identity = identity
        self.method = method
        self.serverName = serverName
        self.tunnelIP = tunnelIP
        self.serverTunnelIP = serverTunnelIP
        self.serverPublicKey = serverPublicKey
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        sessionID = try values.decodeIfPresent(String.self, forKey: .sessionID) ?? ""
        token = try values.decodeIfPresent(String.self, forKey: .token) ?? ""
        ttlSeconds = try values.decodeIfPresent(Int.self, forKey: .ttlSeconds) ?? 0
        tunnels = try values.decodeIfPresent([TunnelGrant].self, forKey: .tunnels) ?? []
        identity = try values.decodeIfPresent(String.self, forKey: .identity) ?? ""
        method = try values.decodeIfPresent(String.self, forKey: .method) ?? ""
        serverName = try values.decodeIfPresent(String.self, forKey: .serverName) ?? ""
        tunnelIP = try values.decodeIfPresent(String.self, forKey: .tunnelIP) ?? ""
        serverTunnelIP = try values.decodeIfPresent(String.self, forKey: .serverTunnelIP) ?? ""
        serverPublicKey = try values.decodeIfPresent(String.self, forKey: .serverPublicKey) ?? ""
    }
}
