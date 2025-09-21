# 🍏 SecureFileApp – iOS SwiftUI Prototype  

This is the **iOS SwiftUI implementation** of the SecureFileApp project.  
It provides file encryption and decryption with a simple UI, file picker, preview, and export options.  

---

## ⚙️ Requirements
- macOS + Xcode 14+  
- iOS 15+ device or simulator  

---

## ▶️ Run
1. Open `SecureFileAppMobile.xcodeproj` in **Xcode**.  
2. Select a simulator or iOS device.  
3. Run the project.  

---

## 🔑 Login
Use the prototype credentials to sign in:  
- **Username**: `nabeel`  
- **Password**: `Nabeel@123`  

---

## 🛠 Features
- File picker (import from iOS Files app).  
- Encrypt and decrypt files with AES-GCM.  
- RSA key wrapping/unwrapping stored in **Keychain**.  
- Preview decrypted text files.  
- Export decrypted files via iOS share sheet.  

---

## 📌 Notes
- Credentials are hardcoded (for prototype only).  
- File previews are text-only. Binary files will show `[Binary content or no preview]`.  
- Built for research/dissertation purposes.  
