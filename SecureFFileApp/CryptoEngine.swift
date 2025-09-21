
import Foundation
import CryptoKit

enum CryptoError: Error, LocalizedError {
    case fileNotFound(String)
    case notAReadableFile(String)
    case cannotCreateOutFile(String)
    case headerTooLarge
    case badMagic
    case badVersion
    case corruptHeader
    case decryptFailed
    case rsaWrapFailed
    case rsaUnwrapFailed
    case io(String)

    var errorDescription: String? {
        switch self {
        case .fileNotFound(let p): return "File not found: \(p)"
        case .notAReadableFile(let p): return "Not a readable file: \(p)"
        case .cannotCreateOutFile(let p): return "Cannot create output file: \(p)"
        case .headerTooLarge: return "Header JSON too large"
        case .badMagic: return "Bad file magic"
        case .badVersion: return "Unsupported file version"
        case .corruptHeader: return "Corrupt header / AAD"
        case .decryptFailed: return "Decryption failed"
        case .rsaWrapFailed: return "Key wrapping failed"
        case .rsaUnwrapFailed: return "Key unwrapping failed"
        case .io(let s): return "I/O error: \(s)"
        }
    }
}

enum CryptoEngine {

    static func encryptFile(
        srcPath: String,
        outPath: String,
        allowedUsers: [String] = [],
        currentUser: String,
        rsaWrap: (_ dek: Data) throws -> Data
    ) throws {

        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: srcPath, isDirectory: &isDir), !isDir.boolValue else {
            throw CryptoError.fileNotFound(srcPath)
        }
        guard FileManager.default.isReadableFile(atPath: srcPath) else {
            throw CryptoError.notAReadableFile(srcPath)
        }

        if FileManager.default.fileExists(atPath: outPath) {
            try? FileManager.default.removeItem(atPath: outPath)
        }
        guard FileManager.default.createFile(atPath: outPath, contents: nil) else {
            throw CryptoError.cannotCreateOutFile(outPath)
        }

        let inURL  = URL(fileURLWithPath: srcPath)
        let outURL = URL(fileURLWithPath: outPath)

        guard let inFH = try? FileHandle(forReadingFrom: inURL),
              let outFH = try? FileHandle(forWritingTo: outURL) else {
            throw CryptoError.io("Could not open file handles")
        }
        defer {
            try? inFH.close()
            try? outFH.close()
        }
        let dek  = SymmetricKey(size: .bits256)
        let nRaw = AES.GCM.Nonce()
        let nonceData = Data(nRaw)

        let wrappedDEK: Data
        do {
            wrappedDEK = try rsaWrap(Data(dek.withUnsafeBytes { Data($0) }))
        } catch {
            throw CryptoError.rsaWrapFailed
        }

        var header = EncHeader()
        header.magic    = EncHeader.magicString
        header.version  = 1
        header.owner    = currentUser
        header.allowed  = allowedUsers
        header.nonceB64 = nonceData.base64EncodedString()
        header.encDEKB64 = wrappedDEK.base64EncodedString()
        header.created  = ISO8601DateFormatter().string(from: Date())

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let headerJSON = try encoder.encode(header)
        guard headerJSON.count <= EncHeader.maxHeaderLen else { throw CryptoError.headerTooLarge }

        try outFH.write(contentsOf: EncHeader.magicData)
        try outFH.write(u32: UInt32(headerJSON.count))
        try outFH.write(contentsOf: headerJSON)

        let aad = EncHeader.magicData + Data(try u32be(UInt32(headerJSON.count))) + headerJSON

        var sealedStream = AESGCMStream.Encryptor(key: dek, nonce: nRaw, aad: aad)
        while let chunk = try inFH.read(upToCount: 1_048_576), !chunk.isEmpty {
            let ct = try sealedStream.update(plaintext: chunk)
            if !ct.isEmpty { try outFH.write(contentsOf: ct) }
        }
        let final = try sealedStream.finalize()
        if !final.isEmpty { try outFH.write(contentsOf: final) }
    }

 
    @discardableResult
    static func decryptFile(
        srcPath: String,
        outPath: String,
        username: String,
        rsaUnwrap: (_ wrappedDEK: Data) throws -> Data
    ) throws -> Data {

        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: srcPath, isDirectory: &isDir), !isDir.boolValue else {
            throw CryptoError.fileNotFound(srcPath)
        }
        if FileManager.default.fileExists(atPath: outPath) {
            try? FileManager.default.removeItem(atPath: outPath)
        }
        guard FileManager.default.createFile(atPath: outPath, contents: nil) else {
            throw CryptoError.cannotCreateOutFile(outPath)
        }

        let inURL  = URL(fileURLWithPath: srcPath)
        let outURL = URL(fileURLWithPath: outPath)

        guard let inFH = try? FileHandle(forReadingFrom: inURL),
              let outFH = try? FileHandle(forWritingTo: outURL) else {
            throw CryptoError.io("Could not open file handles")
        }
        defer {
            try? inFH.close()
            try? outFH.close()
        }

        let magic = try inFH.readExactly(count: EncHeader.magicData.count)
        guard magic == EncHeader.magicData else { throw CryptoError.badMagic }
        let hlen = try inFH.readU32()
        let hjson = try inFH.readExactly(count: Int(hlen))

        let decoder = JSONDecoder()
        let header = try decoder.decode(EncHeader.self, from: hjson)
        guard header.magic == EncHeader.magicString, header.version == 1 else {
            throw CryptoError.badVersion
        }

        let aad = EncHeader.magicData + Data(try u32be(hlen)) + hjson

        guard let nonceData = Data(base64Encoded: header.nonceB64),
              let wrappedDEK = Data(base64Encoded: header.encDEKB64),
              let nonce = try? AES.GCM.Nonce(data: nonceData) else {
            throw CryptoError.corruptHeader
        }

        let dekBytes: Data
        do {
            dekBytes = try rsaUnwrap(wrappedDEK)
        } catch {
            throw CryptoError.rsaUnwrapFailed
        }
        let dek = SymmetricKey(data: dekBytes)

        var opened = AESGCMStream.Decryptor(key: dek, nonce: nonce, aad: aad)

        var preview = Data()
        while let chunk = try inFH.read(upToCount: 1_048_576), !chunk.isEmpty {
            let pt = try opened.update(ciphertext: chunk)
            if !pt.isEmpty {
                try outFH.write(contentsOf: pt)
                if preview.count < 4096 { preview.append(pt.prefix(4096 - preview.count)) }
            }
        }
        let tail = try opened.finalize()
        if !tail.isEmpty {
            try outFH.write(contentsOf: tail)
            if preview.count < 4096 { preview.append(tail.prefix(4096 - preview.count)) }
        }

        return preview
    }
}


private struct EncHeader: Codable {
    static let magicString = "SFA1"
    static let magicData   = Data(magicString.utf8)
    static let maxHeaderLen = 16 * 1024

    var magic: String = magicString
    var version: Int = 1
    var nonceB64: String = ""
    var encDEKB64: String = ""
    var owner: String = ""
    var allowed: [String] = []
    var created: String = ""
}

private enum AESGCMStream {

    struct Encryptor {
        private let key: SymmetricKey
        private let nonce: AES.GCM.Nonce
        private let aad: Data
        private var ctx: AES.GCM.SealedBox? = nil

        init(key: SymmetricKey, nonce: AES.GCM.Nonce, aad: Data) {
            self.key = key
            self.nonce = nonce
            self.aad = aad
        }

        mutating func update(plaintext: Data) throws -> Data {
            let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
            self.ctx = sealed
            return sealed.ciphertext
        }

        mutating func finalize() throws -> Data {
            guard let s = ctx else { return Data() }
            return s.tag
        }
    }

    struct Decryptor {
        private let key: SymmetricKey
        private let nonce: AES.GCM.Nonce
        private let aad: Data
        private var buffer = Data()

        init(key: SymmetricKey, nonce: AES.GCM.Nonce, aad: Data) {
            self.key = key
            self.nonce = nonce
            self.aad = aad
        }

        mutating func update(ciphertext: Data) throws -> Data {
            buffer.append(ciphertext)
            
            return Data()
        }

        mutating func finalize() throws -> Data {
          
            guard buffer.count >= 16 else { throw CryptoError.decryptFailed }
            let tag = buffer.suffix(16)
            let body = buffer.dropLast(16)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: body, tag: tag)
            let pt = try AES.GCM.open(sealed, using: key, authenticating: aad)
            buffer.removeAll(keepingCapacity: false)
            return pt
        }
    }
}

private extension FileHandle {

    func readExactly(count: Int) throws -> Data {
        var out = Data()
        while out.count < count {
            if let chunk = try read(upToCount: count - out.count), !chunk.isEmpty {
                out.append(chunk)
            } else {
                throw CryptoError.io("Unexpected EOF")
            }
        }
        return out
    }

    func readU32() throws -> UInt32 {
        let d = try readExactly(count: 4)
        return d.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }

    func write(u32: UInt32) throws {
        var be = u32.bigEndian
        let d = Data(bytes: &be, count: 4)
        try write(contentsOf: d)
    }
}

private func u32be(_ v: UInt32) throws -> [UInt8] {
    var be = v.bigEndian
    return withUnsafeBytes(of: &be) { Array($0) }
}
