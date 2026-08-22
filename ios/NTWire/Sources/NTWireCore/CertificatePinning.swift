import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif

/// Computes the same "SHA256:<base64>" fingerprint the server displays
/// (`TLSManager.Fingerprint` in pkg/server/tls.go), so a pin captured on
/// either side can be compared or shown to the user verbatim.
public enum CertificateFingerprint {
    public static func sha256Pin(for derEncodedCertificate: Data) -> String {
        let digest = SHA256.hash(data: derEncodedCertificate)
        let base64 = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(base64)"
    }
}

/// Reported by `PinningURLSessionDelegate` (never auto-accepted) whenever the
/// presented certificate doesn't match what's already pinned for a profile —
/// including the very first connection, where nothing is pinned yet. Mirrors
/// the `ntwire` CLI's `UnknownCertificateError` (pkg/client/client.go): the
/// handshake fails closed and the caller must get explicit user confirmation
/// before retrying with this fingerprint pinned.
public struct UntrustedServerCertificateError: Error, LocalizedError, Equatable, Sendable {
    public let presentedPin: String
    /// The profile's previously pinned fingerprint, or `nil` on a first
    /// connection where nothing has been pinned yet.
    public let previousPin: String?

    public init(presentedPin: String, previousPin: String?) {
        self.presentedPin = presentedPin
        self.previousPin = previousPin
    }

    public var errorDescription: String? {
        guard let previousPin else {
            return "This is the first connection to this server. Its certificate fingerprint is \(presentedPin) — verify it against the server's own startup log before trusting it."
        }
        return "The server presented a different certificate than the one pinned for this profile (expected \(previousPin), got \(presentedPin)). This happens if the server's certificate was regenerated, or if the connection is being intercepted. Only trust the new fingerprint if you can confirm it with the server operator."
    }
}

#if canImport(Security)
/// Implements the trust-on-first-use model described in docs/IOS.md: ntwire's
/// server listeners commonly use a self-signed certificate, so normal system
/// PKI validation is not meaningful here. The delegate never falls back to
/// system trust evaluation and never auto-trusts a certificate on its own —
/// including on first connect — so the caller can prompt for explicit
/// confirmation first, exactly as the `ntwire` CLI does.
public final class PinningURLSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let expectedPin: String?
    private let onUntrustedCertificate: (@Sendable (UntrustedServerCertificateError) -> Void)?
    private let onChallenge: (@Sendable (_ challengeNumber: Int, _ accepted: Bool) -> Void)?
    private var challengeCount = 0

    /// - Parameters:
    ///   - expectedPin: the previously pinned fingerprint, or `nil` if this
    ///     profile hasn't trusted a certificate yet.
    ///   - onUntrustedCertificate: invoked once, synchronously with the
    ///     challenge, whenever the presented certificate isn't an exact match
    ///     for `expectedPin` (including when `expectedPin` is `nil`). The
    ///     handshake is always cancelled in that case; this only lets the
    ///     caller report a specific, actionable error instead of the
    ///     system's generic TLS failure.
    ///   - onChallenge: invoked on every server-trust challenge this delegate
    ///     receives, with a 1-based count and whether it was accepted. Lets a
    ///     caller distinguish "the delegate was never consulted" from "it
    ///     accepted, but something else in the connection failed afterward"
    ///     when a request fails without going through `onUntrustedCertificate`.
    public init(
        expectedPin: String?,
        onUntrustedCertificate: (@Sendable (UntrustedServerCertificateError) -> Void)? = nil,
        onChallenge: (@Sendable (Int, Bool) -> Void)? = nil
    ) {
        self.expectedPin = expectedPin
        self.onUntrustedCertificate = onUntrustedCertificate
        self.onChallenge = onChallenge
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let (disposition, credential) = evaluate(trust)
        completionHandler(disposition, credential)
    }

    /// The pinning decision, isolated from `URLAuthenticationChallenge` so it
    /// can be exercised directly against a `SecTrust` in tests.
    func evaluate(_ trust: SecTrust) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        challengeCount += 1
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            onChallenge?(challengeCount, false)
            return (.cancelAuthenticationChallenge, nil)
        }
        let presentedPin = CertificateFingerprint.sha256Pin(for: SecCertificateCopyData(leaf) as Data)
        guard let expectedPin, presentedPin == expectedPin else {
            onUntrustedCertificate?(UntrustedServerCertificateError(presentedPin: presentedPin, previousPin: expectedPin))
            onChallenge?(challengeCount, false)
            return (.cancelAuthenticationChallenge, nil)
        }
        onChallenge?(challengeCount, true)
        return (.useCredential, URLCredential(trust: trust))
    }
}
#endif
