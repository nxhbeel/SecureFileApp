import SwiftUI
import UniformTypeIdentifiers
import UIKit
import QuickLook

struct FileShareView: UIViewControllerRepresentable {
    let fileURL: URL
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

struct QuickLookPreview: UIViewControllerRepresentable {
    final class Coordinator: NSObject, QLPreviewControllerDataSource {
        let url: URL
        init(url: URL) { self.url = url }
        func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }
        func previewController(_ controller: QLPreviewController,
                               previewItemAt index: Int) -> QLPreviewItem { url as QLPreviewItem }
    }
    let url: URL
    func makeCoordinator() -> Coordinator { Coordinator(url: url) }
    func makeUIViewController(context: Context) -> QLPreviewController {
        let ql = QLPreviewController(); ql.dataSource = context.coordinator; return ql
    }
    func updateUIViewController(_ vc: QLPreviewController, context: Context) {}
}

struct ContentView: View {
    @AppStorage("isAuthed") private var isAuthed = false

    
    @State private var inputURL: URL?
    @State private var encURL: URL?
    @State private var decURL: URL?
    @State private var previewText: String = ""
    @State private var message: String = ""
    @State private var showShare = false
    @State private var showQuickLook = false

    private let currentUser = "nabeel"

    var body: some View {
        Group {
            if isAuthed {
                dashboardView
            } else {
                LoginView()            }
        }
        .onAppear { try? KeychainStore.ensureDefaultKeypair() }
    }

    private var dashboardView: some View {
        NavigationView {
            VStack(spacing: 18) {
                Text("📁 SecureFileApp – iOS Prototype")
                    .font(.title3).bold()

                Button("Choose File...") { pickFile() }
                    .buttonStyle(.borderedProminent)

                if let input = inputURL {
                    Text("Selected: \(input.lastPathComponent)")
                        .font(.footnote).foregroundColor(.secondary)
                }

                HStack {
                    Button("Encrypt") { encryptAction() }
                        .buttonStyle(.borderedProminent)
                        .disabled(inputURL == nil)

                    Button("Decrypt") { decryptAction() }
                        .buttonStyle(.bordered)
                        .disabled(encURL == nil)
                }

                if !message.isEmpty {
                    Text(message)
                        .font(.footnote)
                        .foregroundColor(message.hasPrefix("✅") ? .green : .red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                GroupBox("Preview:") {
                    if isTextPreview, !previewText.isEmpty {
                        ScrollView {
                            Text(previewText)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .font(.body)
                                .padding(.top, 4)
                        }
                        .frame(height: 220)
                    } else {
                        VStack(spacing: 10) {
                            Text("[Binary content or no preview]")
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .font(.body)
                                .padding(.top, 4)

                            if let decURL, isQuickLookable(decURL) {
                                Button("Preview") { showQuickLook = true }
                                    .buttonStyle(.bordered)
                                    .sheet(isPresented: $showQuickLook) {
                                        QuickLookPreview(url: decURL)
                                    }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .frame(height: 220)
                    }
                }

                if let dec = decURL {
                    Button("Export Last File") { showShare = true }
                        .buttonStyle(.borderedProminent)
                        .sheet(isPresented: $showShare) {
                            FileShareView(fileURL: dec)
                        }
                        .padding(.top, 6)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Dashboard")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Sign out") { signOut() }
                }
            }
        }
    }

    private var isTextPreview: Bool { !previewText.isEmpty }

    private func isQuickLookable(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        return ["pdf","doc","docx","rtf","pages","ppt","pptx","xls","xlsx",
                "jpg","jpeg","png","gif","heic","txt","csv","json","md"].contains(ext)
    }

    private func isTextFile(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        return ["txt","md","json","csv","log"].contains(ext)
    }

    private func encryptAction() {
        guard let src = inputURL else { return }
        do {
            let enc = FileManager.default.temporaryDirectory
                .appendingPathComponent(src.deletingPathExtension().lastPathComponent + "_enc.sfa")

            try CryptoEngine.encryptFile(
                srcPath: src.path,
                outPath: enc.path,
                allowedUsers: [currentUser],
                currentUser: currentUser,
                rsaWrap: { dek in
                    try RSAWrap.wrap(dek: dek, publicTag: KeychainStore.publicTag)
                }
            )

            encURL = enc
            message = "✅ Encrypted to: \(enc.lastPathComponent)"
            previewText = ""
            decURL = nil
        } catch {
            message = "❌ Encrypt failed: \(error.localizedDescription)"
        }
    }

    private func decryptAction() {
        guard let enc = encURL else { return }
        do {
            let dec = FileManager.default.temporaryDirectory
                .appendingPathComponent(enc.deletingPathExtension().lastPathComponent + "_dec")

            let content = try CryptoEngine.decryptFile(
                srcPath: enc.path,
                outPath: dec.path,
                username: currentUser,
                rsaUnwrap: { wrapped in
                    try RSAWrap.unwrap(wrapped: wrapped, privateTag: KeychainStore.privateTag)
                }
            )

            decURL = dec
            if isTextFile(dec), let text = String(data: content, encoding: .utf8) {
                previewText = text
            } else {
                previewText = ""
            }
            message = "✅ Decrypted to: \(dec.lastPathComponent)"
        } catch {
            message = "❌ Decrypt failed: \(error.localizedDescription)"
        }
    }

    private func signOut() {
        inputURL = nil; encURL = nil; decURL = nil
        previewText = ""; message = ""; showShare = false; showQuickLook = false
        isAuthed = false
    }

    private func pickFile() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [UTType.data], asCopy: true)
        picker.allowsMultipleSelection = false

        let delegate = FilePickerDelegate { url in
            self.inputURL = url
            self.encURL = nil
            self.decURL = nil
            self.previewText = ""
            self.message = ""
        }
        picker.delegate = delegate
        picker.presentationController?.delegate = delegate

        if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = scene.windows.first?.rootViewController {
            objc_setAssociatedObject(picker, &FilePickerDelegate.assocKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
            root.present(picker, animated: true)
        }
    }
}

final class FilePickerDelegate: NSObject, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
    static var assocKey = "FilePickerDelegateKey"
    private let onPick: (URL?) -> Void
    init(onPick: @escaping (URL?) -> Void) { self.onPick = onPick }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        onPick(urls.first); cleanup(controller)
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        onPick(nil); cleanup(controller)
    }
    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        onPick(nil)
    }
    private func cleanup(_ controller: UIDocumentPickerViewController) {
        objc_setAssociatedObject(controller, &FilePickerDelegate.assocKey, nil, .OBJC_ASSOCIATION_ASSIGN)
    }
}
