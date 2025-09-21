import Foundation
import Security

enum RSAWrap {

    static func encrypt(dek: Data, withPublicKeyTag tag: String) throws -> Data {
        guard let pubKey = loadKey(tag: tag, isPublic: true) else {
            throw NSError(domain: "RSAWrap", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Public key not found"])
        }
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(pubKey,
                                                     .rsaEncryptionOAEPSHA256,
                                                     dek as CFData,
                                                     &error) as Data? else {
            throw (error?.takeRetainedValue() as Error?) ??
            NSError(domain: "RSAWrap", code: -2, userInfo: nil)
        }
        return cipher
    }

    static func decrypt(wrapped: Data, withPrivateKeyTag tag: String) throws -> Data {
        guard let privKey = loadKey(tag: tag, isPublic: false) else {
            throw NSError(domain: "RSAWrap", code: -3,
                          userInfo: [NSLocalizedDescriptionKey: "Private key not found"])
        }
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(privKey,
                                                    .rsaEncryptionOAEPSHA256,
                                                    wrapped as CFData,
                                                    &error) as Data? else {
            throw (error?.takeRetainedValue() as Error?) ??
            NSError(domain: "RSAWrap", code: -4, userInfo: nil)
        }
        return plain
    }

   
    static func wrap(dek: Data, publicTag: String) throws -> Data {
        try encrypt(dek: dek, withPublicKeyTag: publicTag)
    }

    static func unwrap(wrapped: Data, privateTag: String) throws -> Data {
        try decrypt(wrapped: wrapped, withPrivateKeyTag: privateTag)
    }

    private static func loadKey(tag: String, isPublic: Bool) -> SecKey? {
        let tagData = tag.data(using: .utf8)!
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tagData,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecReturnRef: true
        ]
        query[kSecAttrKeyClass] = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let cf = item,
              CFGetTypeID(cf) == SecKeyGetTypeID() else {
            return nil
        }
        return (cf as! SecKey)
    }
}
