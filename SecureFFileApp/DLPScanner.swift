import Foundation

enum DLPScanner {
    static let patterns: [(String, NSRegularExpression)] = {
        let rx: [(String,String)] = [
            ("Passwords", #"password\s*[:=]\s*\S+"#),
            ("Emails", #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#),
            ("Credit Cards", #"\b(?:\d[ -]*?){13,16}\b"#)
        ]
        return rx.map { ($0.0, try! NSRegularExpression(pattern: $0.1, options: [.caseInsensitive])) }
    }()

    static func scanHead(of path: String, bytes: Int = 256*1024) -> [String] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return [] }
        let head = data.prefix(bytes)
        guard let text = String(data: head, encoding: .utf8) else { return [] }
        var hits: [String] = []
        for (label, rx) in patterns {
            if rx.firstMatch(in: text, options: [], range: NSRange(text.startIndex..<text.endIndex, in: text)) != nil {
                hits.append(label)
            }
        }
        return hits
    }
}
