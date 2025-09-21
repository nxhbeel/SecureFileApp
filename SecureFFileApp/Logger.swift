import Foundation

enum Logger {
    static var logPath: String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("performance.jsonl").path
    }
    static func append(kind: String, fields: [String: Any]) {
        var payload = fields
        payload["ts"] = ISO8601DateFormatter().string(from: Date())
        payload["kind"] = kind
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: []),
           let line = String(data: data, encoding: .utf8) {
            if let handle = FileHandle(forWritingAtPath: logPath) {
                handle.seekToEndOfFile()
                try? handle.write(contentsOf: (line + "\n").data(using: .utf8)!)
                try? handle.close()
            } else {
                FileManager.default.createFile(atPath: logPath, contents: (line + "\n").data(using: .utf8))
            }
        }
    }
}
