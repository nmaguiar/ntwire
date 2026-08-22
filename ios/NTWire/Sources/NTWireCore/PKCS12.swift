import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif
#if canImport(Security)
import Security
#endif

#if canImport(CommonCrypto) && canImport(Security)

// Object identifiers used only by the PKCS#12 (RFC 7292) container.
enum PKCS12OID {
    static let data = [1, 2, 840, 113549, 1, 7, 1]
    static let encryptedData = [1, 2, 840, 113549, 1, 7, 6]
    static let certBag = [1, 2, 840, 113549, 1, 12, 10, 1, 3]
    static let pkcs8ShroudedKeyBag = [1, 2, 840, 113549, 1, 12, 10, 1, 2]
    static let x509Certificate = [1, 2, 840, 113549, 1, 9, 22, 1]
    static let localKeyId = [1, 2, 840, 113549, 1, 9, 21]
    static let pbeWithSHAAnd3KeyTripleDESCBC = [1, 2, 840, 113549, 1, 12, 1, 3]
    static let pbeWithSHAAnd40BitRC2CBC = [1, 2, 840, 113549, 1, 12, 1, 6]
    static let sha1 = [1, 3, 14, 3, 2, 26]
}

/// Apple's PKCS#12 importer (and, per docs/IOS.md, almost certainly whatever
/// `NERelay.identityData` uses internally) only accepts the legacy PBE
/// ciphers this predates -- not modern PBES2/AES, which only landed in the
/// macOS 15/iOS 18 generation of the Security framework -- and an HMAC-SHA-1
/// MacData. `.tripleDES` is simplest and used for both cert and key bags;
/// `.rc2_40` for cert bags mimics the traditional `openssl pkcs12 -legacy`
/// shape some importers are more thoroughly exercised against. Which one a
/// real device actually requires is unverified without hardware -- see the
/// plan's risk notes -- so this is a parameter, not a single hardcoded choice.
public enum MASQUEPKCS12CertCipher: Sendable {
    case tripleDES
    case rc2_40
}

public enum MASQUEPKCS12Error: Error, LocalizedError, Sendable {
    case keyExportFailed
    case invalidCertificate
    case cryptoFailed

    public var errorDescription: String? {
        switch self {
        case .keyExportFailed: return "Could not export the local device private key."
        case .invalidCertificate: return "The issued certificate could not be encoded into the relay identity."
        case .cryptoFailed: return "Could not assemble the relay identity container."
        }
    }
}

/// Assembles a password-protected PKCS#12 (RFC 7292) identity -- device key
/// plus the certificate the server issued -- for `NERelay.identityData`.
/// Apple's Security framework can only *import* PKCS#12, not construct one,
/// so this is a from-scratch, dependency-free ASN.1/PBE implementation
/// (matching docs/IOS.md's "dependency-free Swift package" constraint).
/// Only the leaf certificate is included: the gateway
/// (`pkg/server/masque_gateway.go`) validates the presented client
/// certificate against its own configured client CA and doesn't need the
/// issuing CA presented in the mTLS handshake.
public enum MASQUEPKCS12 {
    public static func assemble(
        leafCertificatePEM: String,
        privateKey: SecKey,
        certCipher: MASQUEPKCS12CertCipher = .tripleDES
    ) throws -> (data: Data, password: String) {
        let certDER = try derFromPEM(leafCertificatePEM)
        let password = randomPassword()
        let localKeyId = try randomBytes(count: 20)

        var plaintextKeyInfo = try pkcs8ECPrivateKeyInfo(privateKey: privateKey)
        defer { secureZero(&plaintextKeyInfo) }

        let keySalt = try randomBytes(count: 8)
        let keyIterations = 2048
        let (keyCiphertext, keyAlgorithm) = try pbeEncrypt(
            plaintext: plaintextKeyInfo, password: password, salt: keySalt, iterations: keyIterations,
            cipher: .tripleDES, oid: PKCS12OID.pbeWithSHAAnd3KeyTripleDESCBC
        )
        let encryptedKeyInfo = encryptedPrivateKeyInfoDER(algorithmDER: keyAlgorithm, ciphertext: keyCiphertext)
        let keyBag = safeBagDER(bagId: PKCS12OID.pkcs8ShroudedKeyBag, bagValueDER: encryptedKeyInfo, localKeyId: localKeyId)
        var keySafeBags = DERWriter()
        keySafeBags.appendSequence { seq in seq.appendVerbatim(keyBag) }
        let keyContentInfo = contentInfoData(keySafeBags.bytes)

        let certBagContent = certBagDER(certDER: certDER)
        let certBag = safeBagDER(bagId: PKCS12OID.certBag, bagValueDER: certBagContent, localKeyId: localKeyId)
        var certSafeBags = DERWriter()
        certSafeBags.appendSequence { seq in seq.appendVerbatim(certBag) }
        let certSalt = try randomBytes(count: 8)
        let certIterations = 2048
        let (certCiphertext, certAlgorithm) = try pbeEncrypt(
            plaintext: certSafeBags.bytes, password: password, salt: certSalt, iterations: certIterations,
            cipher: certCipher,
            oid: certCipher == .tripleDES ? PKCS12OID.pbeWithSHAAnd3KeyTripleDESCBC : PKCS12OID.pbeWithSHAAnd40BitRC2CBC
        )
        let certEncryptedContentInfo = encryptedContentInfoDER(algorithmDER: certAlgorithm, ciphertext: certCiphertext)
        let certContentInfo = contentInfoEncryptedDataDER(certEncryptedContentInfo)

        var authenticatedSafe = DERWriter()
        authenticatedSafe.appendSequence { seq in
            seq.appendVerbatim(certContentInfo)
            seq.appendVerbatim(keyContentInfo)
        }
        let authSafeDER = authenticatedSafe.bytes

        let authSafeContentInfo = contentInfoData(authSafeDER)

        let macSalt = try randomBytes(count: 8)
        let macIterations = 2048
        let mac = macDataDER(authenticatedSafeDER: authSafeDER, password: password, salt: macSalt, iterations: macIterations)

        var pfx = DERWriter()
        pfx.appendSequence { seq in
            seq.appendInteger(3)
            seq.appendVerbatim(authSafeContentInfo)
            seq.appendVerbatim(mac)
        }
        return (pfx.bytes, password)
    }

    // MARK: - PKCS#8 EC private key

    private static func pkcs8ECPrivateKeyInfo(privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard var raw = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw MASQUEPKCS12Error.keyExportFailed
        }
        defer { secureZero(&raw) }
        // P-256 external representation: 04 || X(32) || Y(32) || K(32) = 97 bytes.
        guard raw.count == 97, raw.first == 0x04 else { throw MASQUEPKCS12Error.keyExportFailed }
        let point = Data(raw.prefix(65))
        var scalar = Data(raw.suffix(32))
        defer { secureZero(&scalar) }

        var ecPrivateKey = DERWriter()
        ecPrivateKey.appendSequence { seq in
            seq.appendInteger(1)
            seq.appendOctetString(scalar)
            seq.appendExplicit(1) { exp in exp.appendBitString(point) }
        }

        var info = DERWriter()
        info.appendSequence { seq in
            seq.appendInteger(0)
            seq.appendSequence { alg in
                alg.appendOID(ASN1OID.ecPublicKey)
                alg.appendOID(ASN1OID.prime256v1)
            }
            seq.appendOctetString(ecPrivateKey.bytes)
        }
        return info.bytes
    }

    private static func encryptedPrivateKeyInfoDER(algorithmDER: Data, ciphertext: Data) -> Data {
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendVerbatim(algorithmDER)
            seq.appendOctetString(ciphertext)
        }
        return w.bytes
    }

    // MARK: - Bags

    private static func certBagDER(certDER: Data) -> Data {
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendOID(PKCS12OID.x509Certificate)
            seq.appendExplicit(0) { exp in exp.appendOctetString(certDER) }
        }
        return w.bytes
    }

    private static func safeBagDER(bagId: [Int], bagValueDER: Data, localKeyId: Data) -> Data {
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendOID(bagId)
            seq.appendExplicit(0) { exp in exp.appendVerbatim(bagValueDER) }
            seq.appendSet { attrs in
                attrs.appendSequence { attr in
                    attr.appendOID(PKCS12OID.localKeyId)
                    attr.appendSet { vals in vals.appendOctetString(localKeyId) }
                }
            }
        }
        return w.bytes
    }

    // MARK: - ContentInfo wrappers

    private static func contentInfoData(_ content: Data) -> Data {
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendOID(PKCS12OID.data)
            seq.appendExplicit(0) { exp in exp.appendOctetString(content) }
        }
        return w.bytes
    }

    /// `EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm,
    /// encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }` -- the `[0]` here
    /// is IMPLICIT (RFC 5652 CMS convention), so it directly replaces the
    /// OCTET STRING tag rather than wrapping it; using `appendRaw(0x80, ...)`
    /// (context, primitive, tag 0) rather than `appendExplicit` is deliberate.
    private static func encryptedContentInfoDER(algorithmDER: Data, ciphertext: Data) -> Data {
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendOID(PKCS12OID.data)
            seq.appendVerbatim(algorithmDER)
            seq.appendRaw(0x80, ciphertext)
        }
        return w.bytes
    }

    /// `EncryptedData ::= SEQUENCE { version CMSVersion, encryptedContentInfo
    /// EncryptedContentInfo }` (RFC 5652) -- the `content` an `encryptedData`
    /// ContentInfo carries is this whole structure, not `EncryptedContentInfo`
    /// directly; version is 0 here (no `unprotectedAttrs`).
    private static func contentInfoEncryptedDataDER(_ encryptedContentInfoDER: Data) -> Data {
        var encryptedData = DERWriter()
        encryptedData.appendSequence { seq in
            seq.appendInteger(0)
            seq.appendVerbatim(encryptedContentInfoDER)
        }
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendOID(PKCS12OID.encryptedData)
            seq.appendExplicit(0) { exp in exp.appendVerbatim(encryptedData.bytes) }
        }
        return w.bytes
    }

    // MARK: - MacData

    /// The MAC covers exactly the DER bytes of the `AuthenticatedSafe`
    /// SEQUENCE -- not the OCTET STRING tag/length that wraps it inside
    /// `authSafe.content`, and not the `[0] EXPLICIT` wrapper around that.
    /// Kept as its own function so there's nowhere to accidentally re-wrap it.
    private static func macDataDER(authenticatedSafeDER: Data, password: String, salt: Data, iterations: Int) -> Data {
        let macKey = PKCS12KDF.derive(id: .mac, password: password, salt: salt, iterations: iterations, outputLength: 20)
        let digest = hmacSHA1(key: macKey, message: authenticatedSafeDER)
        var w = DERWriter()
        w.appendSequence { seq in
            seq.appendSequence { digestInfo in
                digestInfo.appendSequence { alg in
                    alg.appendOID(PKCS12OID.sha1)
                    alg.appendNull()
                }
                digestInfo.appendOctetString(digest)
            }
            seq.appendOctetString(salt)
            seq.appendInteger(iterations)
        }
        return w.bytes
    }

    // MARK: - PBE encryption

    private static func pbeEncrypt(
        plaintext: Data, password: String, salt: Data, iterations: Int,
        cipher: MASQUEPKCS12CertCipher, oid: [Int]
    ) throws -> (ciphertext: Data, algorithmDER: Data) {
        let keyLength = cipher == .tripleDES ? 24 : 5
        var key = PKCS12KDF.derive(id: .key, password: password, salt: salt, iterations: iterations, outputLength: keyLength)
        defer { secureZero(&key) }
        let iv = PKCS12KDF.derive(id: .iv, password: password, salt: salt, iterations: iterations, outputLength: 8)
        let ciphertext = try cbcEncrypt(algorithm: cipher == .tripleDES ? CCAlgorithm(kCCAlgorithm3DES) : CCAlgorithm(kCCAlgorithmRC2), key: key, iv: iv, plaintext: plaintext)

        var algorithm = DERWriter()
        algorithm.appendSequence { seq in
            seq.appendOID(oid)
            seq.appendSequence { params in
                params.appendOctetString(salt)
                params.appendInteger(iterations)
            }
        }
        return (ciphertext, algorithm.bytes)
    }

    private static func cbcEncrypt(algorithm: CCAlgorithm, key: Data, iv: Data, plaintext: Data) throws -> Data {
        let blockSize = 8
        var outBuffer = [UInt8](repeating: 0, count: plaintext.count + blockSize)
        var moved = 0
        let status = key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
            iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                plaintext.withUnsafeBytes { ptBuf -> CCCryptorStatus in
                    CCCrypt(
                        CCOperation(kCCEncrypt), algorithm, CCOptions(kCCOptionPKCS7Padding),
                        keyBuf.baseAddress, key.count, ivBuf.baseAddress,
                        ptBuf.baseAddress, plaintext.count,
                        &outBuffer, outBuffer.count, &moved
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw MASQUEPKCS12Error.cryptoFailed }
        return Data(outBuffer.prefix(moved))
    }

    // MARK: - Randomness

    private static func randomPassword() -> String {
        (try? randomBytes(count: 16).map { String(format: "%02x", $0) }.joined()) ?? UUID().uuidString
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw MASQUEPKCS12Error.cryptoFailed
        }
        return Data(bytes)
    }
}

func secureZero(_ data: inout Data) {
    data.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else { return }
        memset(base, 0, raw.count)
    }
}

func sha1(_ data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    data.withUnsafeBytes { buf in
        _ = CC_SHA1(buf.baseAddress, CC_LONG(data.count), &digest)
    }
    return Data(digest)
}

func hmacSHA1(key: Data, message: Data) -> Data {
    var mac = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    key.withUnsafeBytes { keyBuf in
        message.withUnsafeBytes { msgBuf in
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), keyBuf.baseAddress, key.count, msgBuf.baseAddress, message.count, &mac)
        }
    }
    return Data(mac)
}

/// RFC 7292 Appendix B.2's password-based key derivation function. Distinct
/// from -- and not to be confused with -- PBKDF2; PKCS#12 predates PBKDF2
/// and uses this SHA-1-only construction instead.
enum PKCS12KDF {
    enum ID: UInt8 { case key = 1, iv = 2, mac = 3 }

    private static let v = 64 // SHA-1 block size in bytes
    private static let u = 20 // SHA-1 digest size in bytes

    static func derive(id: ID, password: String, salt: Data, iterations: Int, outputLength n: Int) -> Data {
        let passwordBytes = bmpString(password)
        let sTilde = repeatToBlockMultiple(salt)
        let pTilde = repeatToBlockMultiple(passwordBytes)
        var I = sTilde
        I.append(pTilde)
        let D = Data(repeating: id.rawValue, count: v)

        var output = Data()
        while output.count < n {
            var a = sha1(D + I)
            for _ in 1..<iterations { a = sha1(a) }
            output.append(a)

            if output.count < n {
                var b = Data()
                while b.count < v { b.append(a) }
                b = b.prefix(v)

                var newI = Data()
                var offset = 0
                while offset < I.count {
                    let end = min(offset + v, I.count)
                    newI.append(addWithCarry(I[offset..<end], b))
                    offset = end
                }
                I = newI
            }
        }
        return output.prefix(n)
    }

    /// Password as UTF-16BE (BMP-only; this KDF is only ever used here with
    /// an ASCII, `SecRandomCopyBytes`-generated password) with the required
    /// trailing null terminator.
    private static func bmpString(_ value: String) -> Data {
        var bytes = Data()
        for scalar in value.unicodeScalars {
            let code = UInt16(scalar.value)
            bytes.append(UInt8(code >> 8))
            bytes.append(UInt8(code & 0xFF))
        }
        bytes.append(contentsOf: [0x00, 0x00])
        return bytes
    }

    private static func repeatToBlockMultiple(_ input: Data) -> Data {
        guard !input.isEmpty else { return Data() }
        let targetLength = v * ((input.count + v - 1) / v)
        var result = Data()
        while result.count < targetLength { result.append(input) }
        return result.prefix(targetLength)
    }

    /// `(a + b + 1) mod 2^(8*v)`, both `v`-byte big-endian values; the carry
    /// past the top byte is discarded, per RFC 7292 Appendix B.2.
    private static func addWithCarry(_ a: Data, _ b: Data) -> Data {
        let aBytes = [UInt8](a)
        let bBytes = [UInt8](b)
        var result = [UInt8](repeating: 0, count: aBytes.count)
        var carry = 1
        for i in stride(from: aBytes.count - 1, through: 0, by: -1) {
            let sum = Int(aBytes[i]) + Int(bBytes[i]) + carry
            result[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
        }
        return Data(result)
    }
}
#endif
