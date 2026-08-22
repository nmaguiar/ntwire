import Foundation
#if canImport(Security)
import Security
#endif

public enum MASQUEIdentityError: Error, LocalizedError, Sendable {
    case keyGenerationFailed
    case signingFailed
    case publicKeyExportFailed
    case malformedCertificatePEM

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "Could not generate a local device key for the relay identity."
        case .signingFailed: return "Could not sign the certificate request."
        case .publicKeyExportFailed: return "Could not export the local device public key."
        case .malformedCertificatePEM: return "The server's issued certificate could not be parsed."
        }
    }
}

/// A minimal DER writer covering exactly the ASN.1 constructs the CSR and
/// PKCS#12 builders need. There is no Apple API for constructing (only
/// parsing) either format, and this package stays dependency-free per
/// docs/IOS.md, so both are hand-rolled against `DERReader` (SSHAuthentication.swift).
struct DERWriter {
    private(set) var bytes = Data()

    mutating func appendRaw(_ tag: UInt8, _ content: Data) {
        bytes.append(tag)
        appendLength(content.count)
        bytes.append(content)
    }

    /// Splices in bytes that are already a complete TLV encoding (tag +
    /// length + content) of their own, e.g. a nested structure built and
    /// returned as its own top-level value elsewhere. Using `appendRaw`
    /// instead here would add a second, spurious wrapping tag/length around
    /// content that already has one.
    mutating func appendVerbatim(_ der: Data) { bytes.append(der) }

    mutating func appendSequence(_ build: (inout DERWriter) -> Void) { appendConstructed(0x30, build) }
    mutating func appendSet(_ build: (inout DERWriter) -> Void) { appendConstructed(0x31, build) }

    /// `[n] EXPLICIT` context tag (constructed).
    mutating func appendExplicit(_ tagNumber: UInt8, _ build: (inout DERWriter) -> Void) {
        appendConstructed(0xA0 | tagNumber, build)
    }

    private mutating func appendConstructed(_ tag: UInt8, _ build: (inout DERWriter) -> Void) {
        var inner = DERWriter()
        build(&inner)
        appendRaw(tag, inner.bytes)
    }

    mutating func appendInteger(_ value: Int) {
        precondition(value >= 0, "only non-negative small integers are needed here")
        if value == 0 {
            appendRaw(0x02, Data([0x00]))
            return
        }
        var v = value
        var digits: [UInt8] = []
        while v > 0 {
            digits.append(UInt8(v & 0xFF))
            v >>= 8
        }
        digits.reverse()
        if digits[0] & 0x80 != 0 { digits.insert(0x00, at: 0) }
        appendRaw(0x02, Data(digits))
    }

    mutating func appendOID(_ dotted: [Int]) {
        precondition(dotted.count >= 2)
        var content: [UInt8] = Self.base128(dotted[0] * 40 + dotted[1])
        for component in dotted.dropFirst(2) {
            content.append(contentsOf: Self.base128(component))
        }
        appendRaw(0x06, Data(content))
    }

    private static func base128(_ value: Int) -> [UInt8] {
        var v = value
        var groups: [UInt8] = [UInt8(v & 0x7F)]
        v >>= 7
        while v > 0 {
            groups.append(UInt8(v & 0x7F) | 0x80)
            v >>= 7
        }
        return groups.reversed()
    }

    mutating func appendBitString(_ value: Data, unusedBits: UInt8 = 0) {
        var content = Data([unusedBits])
        content.append(value)
        appendRaw(0x03, content)
    }

    mutating func appendOctetString(_ value: Data) { appendRaw(0x04, value) }
    mutating func appendNull() { appendRaw(0x05, Data()) }
    mutating func appendPrintableString(_ value: String) { appendRaw(0x13, Data(value.utf8)) }

    private mutating func appendLength(_ length: Int) {
        if length < 0x80 {
            bytes.append(UInt8(length))
            return
        }
        var digits: [UInt8] = []
        var v = length
        while v > 0 {
            digits.append(UInt8(v & 0xFF))
            v >>= 8
        }
        digits.reverse()
        bytes.append(0x80 | UInt8(digits.count))
        bytes.append(contentsOf: digits)
    }
}

// Object identifiers shared by the CSR and PKCS#12 builders.
enum ASN1OID {
    static let ecPublicKey = [1, 2, 840, 10045, 2, 1]
    static let prime256v1 = [1, 2, 840, 10045, 3, 1, 7]
    static let ecdsaWithSHA256 = [1, 2, 840, 10045, 4, 3, 2]
    static let commonName = [2, 5, 4, 3]
}

#if canImport(Security)
public enum MASQUEKeyPair {
    /// Generates an exportable, software-backed EC P-256 key pair. Never
    /// Secure Enclave-backed (Network Relay needs a PKCS#12-exportable key,
    /// which a Secure Enclave key can never produce) and never persisted to
    /// the Keychain (`kSecAttrIsPermanent: false`, nested under
    /// `kSecPrivateKeyAttrs` -- a top-level placement is silently ignored and
    /// the key would end up Keychain-resident, which the design forbids).
    public static func generateP256() throws -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw MASQUEIdentityError.keyGenerationFailed
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw MASQUEIdentityError.keyGenerationFailed
        }
        return (privateKey, publicKey)
    }
}

/// Builds the PKCS#10 CSR (RFC 2986) `POST /v1/masque/certificate` expects.
/// The server (`issueMASQUECertificate` in pkg/server/masque.go) validates
/// only the CSR's signature and reads its public key; it mints its own
/// Subject, so the one used here is fixed and carries no device identity.
public enum MASQUECSR {
    private static let subjectCommonName = "ntwire-ios-client"

    public static func build(privateKey: SecKey, publicKey: SecKey) throws -> String {
        let requestInfo = try certificationRequestInfo(publicKey: publicKey)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, requestInfo as CFData, &error) as Data? else {
            throw MASQUEIdentityError.signingFailed
        }
        var writer = DERWriter()
        writer.appendSequence { w in
            w.appendVerbatim(requestInfo) // CertificationRequestInfo, already a complete SEQUENCE TLV
            w.appendSequence { alg in alg.appendOID(ASN1OID.ecdsaWithSHA256) } // signatureAlgorithm, no parameters
            w.appendBitString(signature)
        }
        return pem(writer.bytes, label: "CERTIFICATE REQUEST")
    }

    private static func certificationRequestInfo(publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw MASQUEIdentityError.publicKeyExportFailed
        }
        var writer = DERWriter()
        writer.appendSequence { w in
            w.appendInteger(0) // version
            w.appendSequence { name in // Name (RDNSequence)
                name.appendSet { rdn in
                    rdn.appendSequence { atv in
                        atv.appendOID(ASN1OID.commonName)
                        atv.appendPrintableString(subjectCommonName)
                    }
                }
            }
            w.appendSequence { spki in // SubjectPublicKeyInfo
                spki.appendSequence { alg in
                    alg.appendOID(ASN1OID.ecPublicKey)
                    alg.appendOID(ASN1OID.prime256v1)
                }
                spki.appendBitString(point)
            }
            w.appendRaw(0xA0, Data()) // [0] IMPLICIT SET OF Attribute {}, empty
        }
        return writer.bytes
    }
}

func derFromPEM(_ pem: String) throws -> Data {
    let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }
    guard let der = Data(base64Encoded: lines.joined()) else { throw MASQUEIdentityError.malformedCertificatePEM }
    return der
}

func pem(_ der: Data, label: String) -> String {
    let base64 = der.base64EncodedString()
    var lines = ["-----BEGIN \(label)-----"]
    var index = base64.startIndex
    while index < base64.endIndex {
        let end = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
        lines.append(String(base64[index..<end]))
        index = end
    }
    lines.append("-----END \(label)-----")
    return lines.joined(separator: "\n") + "\n"
}
#endif
