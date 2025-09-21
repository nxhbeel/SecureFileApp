import Foundation
import Security
enum KeychainStore {

    static let publicTag  = "com.securefileapp.default.public"
    static let privateTag = "com.securefileapp.default.private"

    @discardableResult
    static func ensureDefaultKeypair() throws -> (publicTag: String, privateTag: String) {
        if !hasKey(tag: publicTag,  isPublic: true) ||
           !hasKey(tag: privateTag, isPublic: false) {
            try createKeypair(publicTag: publicTag, privateTag: privateTag)
        }
        return (publicTag, privateTag)
    }

    static func deleteDefaultKeypair() {
        _ = deleteKey(tag: publicTag,  isPublic: true)
        _ = deleteKey(tag: privateTag, isPublic: false)
    }

    static func key(tag: String, isPublic: Bool) -> SecKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag.data(using: .utf8)!,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
            kSecReturnRef: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let cf = item,
              CFGetTypeID(cf) == SecKeyGetTypeID() else {
            return nil
        }
       
        return (cf as! SecKey)
    }

    static func hasKey(tag: String, isPublic: Bool) -> Bool {
        key(tag: tag, isPublic: isPublic) != nil
    }
    private static func createKeypair(publicTag: String, privateTag: String) throws {

        let privAttrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
       
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: privateTag.data(using: .utf8)!,
        ]

        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(privAttrs as CFDictionary, &error) else {
            if let err = error?.takeRetainedValue() { throw err }
            throw NSError(domain: "KeychainStore", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to create private key"])
        }

        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw NSError(domain: "KeychainStore", code: -2,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to derive public key"])
        }

        var error2: Unmanaged<CFError>?
        guard let pubDataCF = SecKeyCopyExternalRepresentation(pub, &error2) else {
            if let e = error2?.takeRetainedValue() { throw e }
            throw NSError(domain: "KeychainStore", code: -3,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to export public key"])
        }
        let pubData = pubDataCF as Data

        let pubAddQuery: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag: publicTag.data(using: .utf8)!,
            kSecAttrIsPermanent: true,
            kSecValueData: pubData
        ]

        let addStatus = SecItemAdd(pubAddQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw NSError(domain: "KeychainStore", code: Int(addStatus),
                          userInfo: [NSLocalizedDescriptionKey: "Failed to store public key (\(addStatus))"])
        }
    }

    @discardableResult
    private static func deleteKey(tag: String, isPublic: Bool) -> OSStatus {
        let q: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag: tag.data(using: .utf8)!
        ]
        return SecItemDelete(q as CFDictionary)
    }
}
