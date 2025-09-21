import SwiftUI

struct LoginView: View {
    @AppStorage("isAuthed") private var isAuthed = false
    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    private let validUser = "nabeel"
    private let validPass = "Nabeel@123"

    var body: some View {
        NavigationView {
            VStack(spacing: 18) {
                Text("SecureFileApp")
                    .font(.largeTitle).bold()

                VStack(alignment: .leading, spacing: 10) {
                    Text("Username").font(.footnote)
                    TextField("Enter username", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .textFieldStyle(.roundedBorder)

                    Text("Password").font(.footnote)
                    SecureField("Enter password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(.horizontal)

                Button("Sign In", action: signIn)
                    .frame(maxWidth: .infinity)
                    .buttonStyle(.borderedProminent)
                    .padding(.horizontal)

                if let e = error {
                    Text(e).foregroundColor(.red).font(.footnote)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()
            }
            .padding(.top, 32)
            .navigationTitle("Sign in")
        }
    }

    private func signIn() {
        if username == validUser && password == validPass {
            error = nil
            isAuthed = true
        } else {
            error = "Invalid credentials. Try again."
        }
    }
}
