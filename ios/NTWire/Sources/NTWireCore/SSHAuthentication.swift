import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif
#if canImport(CNtwireBcrypt)
import CNtwireBcrypt
#endif

/// Errors deliberately omit key data and passphrases.
public enum SSHAuthenticationError: Error, Equatable, LocalizedError, Sendable {
    case missingPrivateKey
    case passphraseRequired
    case unsupportedEncryptedPrivateKey
    case unsupportedPrivateKey
    case malformedPrivateKey
    case invalidWireGuardKey

    public var errorDescription: String? {
        switch self {
        case .missingPrivateKey: return "No SSH private key is saved for this profile."
        case .passphraseRequired: return "This SSH private key is encrypted."
        case .unsupportedEncryptedPrivateKey: return "This encrypted SSH key format is not supported by iOS. Export it as an unencrypted PKCS#8 RSA, ECDSA P-256, or Ed25519 key, or use OIDC."
        case .unsupportedPrivateKey: return "Supported SSH keys are unencrypted PKCS#8 RSA, ECDSA P-256, and Ed25519 keys."
        case .malformedPrivateKey: return "The SSH private key is malformed."
        case .invalidWireGuardKey: return "The saved WireGuard key is invalid."
        }
    }
}

/// Produces the exact OpenSSH public-key and signature encodings used by the
/// ntwire Go client. PKCS#8 supports RSA, NIST P-256 ECDSA, and Ed25519.
enum SSHSigner {
    case ed25519(Curve25519.Signing.PrivateKey)
    case ecdsaP256(P256.Signing.PrivateKey)
#if canImport(Security)
    case rsa(SecKey)
#endif
}

public enum SSHPrivateKey {
    public static func requiresPassphrase(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return false }
        return text.contains("BEGIN ENCRYPTED PRIVATE KEY") || text.contains("BEGIN OPENSSH PRIVATE KEY")
    }

    static func signer(from data: Data, passphrase: String? = nil) throws -> SSHSigner {
        if String(data: data, encoding: .utf8)?.contains("BEGIN OPENSSH PRIVATE KEY") == true {
            let raw = try openSSHED25519Seed(data, passphrase: passphrase)
            do { return .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: raw)) }
            catch { throw SSHAuthenticationError.malformedPrivateKey }
        }
        if requiresPassphrase(data) {
            if passphrase == nil || passphrase?.isEmpty == true { throw SSHAuthenticationError.passphraseRequired }
            throw SSHAuthenticationError.unsupportedEncryptedPrivateKey
        }
        let (der, label) = try pemBody(data)
        if label == "RSA PRIVATE KEY" {
            return try rsaSigner(privateDER: der)
        }
        if label == "EC PRIVATE KEY" {
            return try ecdsaP256Signer(privateDER: der)
        }
        let (algorithm, parameters, privateValue) = try pkcs8PrivateKey(der)
        switch algorithm {
        case Data([0x2B, 0x65, 0x70]):
            var value = DERReader(privateValue)
            let raw = try value.value(tag: 0x04)
            guard value.isAtEnd else { throw SSHAuthenticationError.malformedPrivateKey }
            do { return .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: raw)) }
            catch { throw SSHAuthenticationError.malformedPrivateKey }
        case Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]):
            return try rsaSigner(privateDER: privateValue, pkcs8DER: der)
        case Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]):
            guard parameters == Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) else {
                throw SSHAuthenticationError.unsupportedPrivateKey
            }
            return try ecdsaP256Signer(privateDER: privateValue)
        default: throw SSHAuthenticationError.unsupportedPrivateKey
        }
    }

    static func authorizedKey(for signer: SSHSigner) -> String {
        switch signer {
        case .ed25519(let key):
            return "ssh-ed25519 \(Data(sshString("ssh-ed25519") + sshString(key.publicKey.rawRepresentation)).base64EncodedString())"
        case .ecdsaP256(let key):
            let blob = sshString("ecdsa-sha2-nistp256") + sshString("nistp256") + sshString(key.publicKey.x963Representation)
            return "ecdsa-sha2-nistp256 \(blob.base64EncodedString())"
#if canImport(Security)
        case .rsa(let key):
            guard let publicKey = SecKeyCopyPublicKey(key), let der = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { return "" }
            guard let (modulus, exponent) = try? rsaPublicComponents(der) else { return "" }
            let blob = sshString("ssh-rsa") + sshString(sshMPInt(modulus)) + sshString(sshMPInt(exponent))
            return "ssh-rsa \(blob.base64EncodedString())"
#endif
        }
    }

    static func signature(_ payload: Data, with signer: SSHSigner) throws -> String {
        switch signer {
        case .ed25519(let key):
            let signature = try key.signature(for: payload)
            return Data(sshString("ssh-ed25519") + sshString(signature)).base64EncodedString()
        case .ecdsaP256(let key):
            let der = try key.signature(for: payload).derRepresentation
            let (r, s) = try ecdsaSignatureComponents(der)
            let signature = sshString(sshMPInt(r)) + sshString(sshMPInt(s))
            return Data(sshString("ecdsa-sha2-nistp256") + sshString(signature)).base64EncodedString()
#if canImport(Security)
        case .rsa(let key):
            let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
            guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else { throw SSHAuthenticationError.unsupportedPrivateKey }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, algorithm, payload as CFData, &error) as Data? else {
                throw SSHAuthenticationError.malformedPrivateKey
            }
            return Data(sshString("ssh-rsa") + sshString(signature)).base64EncodedString()
#endif
        }
    }

    private static func pemBody(_ data: Data) throws -> (Data, String) {
        guard let text = String(data: data, encoding: .utf8) else {
            throw SSHAuthenticationError.unsupportedPrivateKey
        }
        let labels = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
        guard let label = labels.first(where: { text.contains("-----BEGIN \($0)-----") }) else { throw SSHAuthenticationError.unsupportedPrivateKey }
        let lines = text.split(whereSeparator: \.isNewline)
        let encoded = lines.filter { !$0.hasPrefix("---") }.joined()
        guard let der = Data(base64Encoded: encoded) else { throw SSHAuthenticationError.malformedPrivateKey }
        return (der, label)
    }

    private static func pkcs8PrivateKey(_ der: Data) throws -> (Data, Data?, Data) {
        var outer = DERReader(der)
        var sequence = DERReader(try outer.value(tag: 0x30))
        _ = try sequence.value(tag: 0x02)
        var algorithm = DERReader(try sequence.value(tag: 0x30))
        let oid = try algorithm.value(tag: 0x06)
        let parameters: Data?
        if algorithm.isAtEnd {
            parameters = nil
        } else {
            let (tag, value) = try algorithm.anyValue()
            guard tag == 0x06 || (tag == 0x05 && value.isEmpty) else { throw SSHAuthenticationError.malformedPrivateKey }
            parameters = tag == 0x06 ? value : nil
        }
        guard algorithm.isAtEnd else { throw SSHAuthenticationError.malformedPrivateKey }
        let privateValue = try sequence.value(tag: 0x04)
        guard sequence.isAtEnd, outer.isAtEnd else { throw SSHAuthenticationError.malformedPrivateKey }
        return (oid, parameters, privateValue)
    }

    private static func ecdsaP256Signer(privateDER: Data) throws -> SSHSigner {
        var outer = DERReader(privateDER)
        var sequence = DERReader(try outer.value(tag: 0x30))
        _ = try sequence.value(tag: 0x02)
        let scalar = try sequence.value(tag: 0x04)
        guard scalar.count == 32, outer.isAtEnd else { throw SSHAuthenticationError.malformedPrivateKey }
        do { return .ecdsaP256(try P256.Signing.PrivateKey(rawRepresentation: scalar)) }
        catch { throw SSHAuthenticationError.malformedPrivateKey }
    }

    private static func rsaSigner(privateDER: Data, pkcs8DER: Data? = nil) throws -> SSHSigner {
#if canImport(Security)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: NSNumber(value: try rsaPrivateKeySize(privateDER))
        ]
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(privateDER as CFData, attributes as CFDictionary, &error)
            ?? pkcs8DER.flatMap { SecKeyCreateWithData($0 as CFData, attributes as CFDictionary, &error) }
        guard let key else {
            throw SSHAuthenticationError.malformedPrivateKey
        }
        return .rsa(key)
#else
        throw SSHAuthenticationError.unsupportedPrivateKey
#endif
    }

    private static func openSSHED25519Seed(_ pem: Data, passphrase: String?) throws -> Data {
        guard let text = String(data: pem, encoding: .utf8) else { throw SSHAuthenticationError.malformedPrivateKey }
        let encoded = text.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("---") }.joined()
        guard let body = Data(base64Encoded: encoded) else { throw SSHAuthenticationError.malformedPrivateKey }
        var outer = SSHReader(body)
        guard try outer.bytes(count: 15) == Data("openssh-key-v1\0".utf8) else { throw SSHAuthenticationError.malformedPrivateKey }
        let cipher = try outer.string()
        let kdf = try outer.string()
        let kdfOptions = try outer.stringData()
        guard try outer.uint32() == 1 else { throw SSHAuthenticationError.unsupportedPrivateKey }
        _ = try outer.stringData() // public key; private payload repeats it after decryption
        var privateData = try outer.stringData()
        guard outer.isAtEnd else { throw SSHAuthenticationError.malformedPrivateKey }

        if cipher != "none" {
            guard kdf == "bcrypt", let passphrase, !passphrase.isEmpty else { throw SSHAuthenticationError.passphraseRequired }
            var options = SSHReader(kdfOptions)
            let salt = try options.stringData()
            let rounds = try options.uint32()
            guard options.isAtEnd, (cipher == "aes128-ctr" || cipher == "aes256-ctr"), rounds > 0 && rounds <= 1_000_000 else {
                throw SSHAuthenticationError.unsupportedEncryptedPrivateKey
            }
            let keyLength = cipher == "aes128-ctr" ? 16 : 32
            var keyAndIV = Data(repeating: 0, count: keyLength + 16)
            let status = passphrase.data(using: .utf8)!.withUnsafeBytes { pass in
                salt.withUnsafeBytes { salt in
                    keyAndIV.withUnsafeMutableBytes { output in
                        ntwire_bcrypt_pbkdf(pass.bindMemory(to: UInt8.self).baseAddress, pass.count, salt.bindMemory(to: UInt8.self).baseAddress, salt.count, output.bindMemory(to: UInt8.self).baseAddress, output.count, rounds)
                    }
                }
            }
            guard status == 0 else { throw SSHAuthenticationError.unsupportedEncryptedPrivateKey }
            var clear = Data(repeating: 0, count: privateData.count)
            let decrypted = privateData.withUnsafeBytes { input in
                keyAndIV.withUnsafeBytes { material in
                    clear.withUnsafeMutableBytes { output in
                        ntwire_aes_ctr(input.bindMemory(to: UInt8.self).baseAddress, input.count, material.bindMemory(to: UInt8.self).baseAddress, keyLength, material.bindMemory(to: UInt8.self).baseAddress!.advanced(by: keyLength), output.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
            }
            guard decrypted == 0 else { throw SSHAuthenticationError.unsupportedEncryptedPrivateKey }
            privateData = clear
        } else if kdf != "none" || !kdfOptions.isEmpty {
            throw SSHAuthenticationError.unsupportedPrivateKey
        }

        var key = SSHReader(privateData)
        let check0 = try key.uint32()
        let check1 = try key.uint32()
        guard check0 == check1, try key.string() == "ssh-ed25519" else { throw SSHAuthenticationError.unsupportedPrivateKey }
        let publicKey = try key.stringData()
        let privateKey = try key.stringData()
        _ = try key.string() // comment
        guard publicKey.count == 32, privateKey.count == 64, privateKey.suffix(32) == publicKey else { throw SSHAuthenticationError.malformedPrivateKey }
        return privateKey.prefix(32)
    }
}

private struct SSHReader {
    private let data: Data
    private var index = 0
    init(_ data: Data) { self.data = data }
    var isAtEnd: Bool { index == data.count }
    mutating func uint32() throws -> UInt32 {
        guard index + 4 <= data.count else { throw SSHAuthenticationError.malformedPrivateKey }
        defer { index += 4 }
        return data[index..<(index + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
    }
    mutating func bytes(count: Int) throws -> Data {
        guard count >= 0, index + count <= data.count else { throw SSHAuthenticationError.malformedPrivateKey }
        defer { index += count }
        return Data(data[index..<(index + count)])
    }
    mutating func stringData() throws -> Data { try bytes(count: Int(uint32())) }
    mutating func string() throws -> String {
        guard let value = String(data: try stringData(), encoding: .utf8) else { throw SSHAuthenticationError.malformedPrivateKey }
        return value
    }
}

public enum WireGuardIdentity {
    public static func publicKey(privateKey: Data) throws -> String {
        guard privateKey.count == 32 else { throw SSHAuthenticationError.invalidWireGuardKey }
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation.base64EncodedString()
        } catch { throw SSHAuthenticationError.invalidWireGuardKey }
    }

    public static func makePrivateKey() -> Data { Curve25519.KeyAgreement.PrivateKey().rawRepresentation }
}

public struct SSHAuthenticationRequest: Codable, Sendable {
    public let version = 1
    public let publicKey: String
    public let wireGuardPublicKey: String
    public let timestamp: String
    public let nonce: String
    public let info: SSHClientInfo
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case version
        case publicKey = "public_key"
        case wireGuardPublicKey = "wireguard_public_key"
        case timestamp, nonce, info = "client_info", signature
    }
}

public struct SSHClientInfo: Codable, Sendable {
    public let os: String
    public let arch: String
    public let hostname: String
    public let username: String
    public let clientVersion: String

    enum CodingKeys: String, CodingKey {
        case os, arch, hostname, username
        case clientVersion = "client_version"
    }

    public init(os: String = "iOS", arch: String = "arm64", hostname: String = "", username: String = "", clientVersion: String = "ios") {
        self.os = os; self.arch = arch; self.hostname = hostname; self.username = username; self.clientVersion = clientVersion
    }
}

public enum SSHAuthenticationPayload {
    public static func make(publicKey: String, wireGuardPublicKey: String, timestamp: String, nonce: String, info: SSHClientInfo) -> Data {
        var value = Data("ntwire-auth-v1\0".utf8)
        [publicKey, wireGuardPublicKey, timestamp, nonce, info.os, info.arch, info.hostname, info.username, info.clientVersion].forEach {
            let field = Data($0.utf8)
            var length = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &length) { value.append(contentsOf: $0) }
            value.append(field)
        }
        return value
    }
}

private func sshString(_ value: String) -> Data { sshString(Data(value.utf8)) }
private func sshString(_ value: Data) -> Data {
    var length = UInt32(value.count).bigEndian
    var result = Data()
    withUnsafeBytes(of: &length) { result.append(contentsOf: $0) }
    result.append(value)
    return result
}

/// SSH mpint values are unsigned integers with a leading zero when needed to
/// keep the sign bit clear. ASN.1 INTEGERs use the same convention, but this
/// normalizes both minimally before placing them in an SSH string.
private func sshMPInt(_ value: Data) -> Data {
    let stripped = value.drop(while: { $0 == 0 })
    var result = Data(stripped)
    if result.isEmpty || result[0] & 0x80 != 0 { result.insert(0, at: 0) }
    return result
}

private func ecdsaSignatureComponents(_ der: Data) throws -> (Data, Data) {
    var outer = DERReader(der)
    var sequence = DERReader(try outer.value(tag: 0x30))
    let r = try sequence.value(tag: 0x02)
    let s = try sequence.value(tag: 0x02)
    guard sequence.isAtEnd, outer.isAtEnd, !r.isEmpty, !s.isEmpty else { throw SSHAuthenticationError.malformedPrivateKey }
    return (r, s)
}

#if canImport(Security)
private func rsaPrivateKeySize(_ der: Data) throws -> Int {
    var outer = DERReader(der)
    var sequence = DERReader(try outer.value(tag: 0x30))
    _ = try sequence.value(tag: 0x02) // version
    let modulus = try sequence.value(tag: 0x02)
    guard outer.isAtEnd, !modulus.isEmpty else { throw SSHAuthenticationError.malformedPrivateKey }
    return modulus.drop(while: { $0 == 0 }).count * 8
}

private func rsaPublicComponents(_ der: Data) throws -> (Data, Data) {
    var outer = DERReader(der)
    var sequence = DERReader(try outer.value(tag: 0x30))
    let modulus = try sequence.value(tag: 0x02)
    let exponent = try sequence.value(tag: 0x02)
    guard sequence.isAtEnd, outer.isAtEnd, !modulus.isEmpty, !exponent.isEmpty else { throw SSHAuthenticationError.malformedPrivateKey }
    return (modulus, exponent)
}
#endif

struct DERReader {
    private let data: Data
    private var index = 0
    init(_ data: Data) { self.data = data }
    var isAtEnd: Bool { index == data.count }

    mutating func value(tag: UInt8) throws -> Data {
        let (actualTag, result) = try anyValue()
        guard actualTag == tag else { throw SSHAuthenticationError.malformedPrivateKey }
        return result
    }

    mutating func anyValue() throws -> (UInt8, Data) {
        guard index < data.count else { throw SSHAuthenticationError.malformedPrivateKey }
        let tag = data[index]
        index += 1
        guard index < data.count else { throw SSHAuthenticationError.malformedPrivateKey }
        var length = Int(data[index]); index += 1
        if length & 0x80 != 0 {
            let bytes = length & 0x7F
            guard bytes > 0, bytes <= 4, index + bytes <= data.count else { throw SSHAuthenticationError.malformedPrivateKey }
            length = 0
            for _ in 0..<bytes { length = (length << 8) | Int(data[index]); index += 1 }
        }
        guard length >= 0, index + length <= data.count else { throw SSHAuthenticationError.malformedPrivateKey }
        defer { index += length }
        return (tag, Data(data[index..<(index + length)]))
    }
}
