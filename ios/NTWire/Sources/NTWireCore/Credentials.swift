import Foundation

#if canImport(Security)
import Security
#endif

public protocol CredentialStore: Sendable {
    func read(account: String) throws -> Data?
    func write(_ value: Data, account: String) throws
    func remove(account: String) throws
}

public enum CredentialStoreError: Error, Equatable, Sendable {
    case unavailable
    case invalidAccount
    case keychainStatus(Int32)
}

#if canImport(Security)
/// The production credential store. It deliberately accepts only opaque bytes
/// and never serializes them into profile storage or diagnostics.
public final class KeychainCredentialStore: CredentialStore, @unchecked Sendable {
    private let service: String

    public init(service: String = "ai.ntwire.ios") {
        self.service = service
    }

    public func read(account: String) throws -> Data? {
        guard !account.isEmpty else { throw CredentialStoreError.invalidAccount }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let value = item as? Data else {
            throw CredentialStoreError.keychainStatus(status)
        }
        return value
    }

    public func write(_ value: Data, account: String) throws {
        guard !account.isEmpty else { throw CredentialStoreError.invalidAccount }
        let lookup: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let attributes: [CFString: Any] = [
            kSecValueData: value,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw CredentialStoreError.keychainStatus(updateStatus)
        }
        var insert = lookup
        for (key, value) in attributes { insert[key] = value }
        let insertStatus = SecItemAdd(insert as CFDictionary, nil)
        guard insertStatus == errSecSuccess else { throw CredentialStoreError.keychainStatus(insertStatus) }
    }

    public func remove(account: String) throws {
        guard !account.isEmpty else { throw CredentialStoreError.invalidAccount }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychainStatus(status)
        }
    }
}
#endif

/// Test-safe in-memory implementation. Production iOS code will use the
/// Keychain adapter in the app target; no credential is persisted here.
public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func read(account: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return values[account]
    }

    public func write(_ value: Data, account: String) throws {
        guard !account.isEmpty else { throw CredentialStoreError.invalidAccount }
        lock.lock(); defer { lock.unlock() }
        values[account] = value
    }

    public func remove(account: String) throws {
        lock.lock(); defer { lock.unlock() }
        values.removeValue(forKey: account)
    }
}
