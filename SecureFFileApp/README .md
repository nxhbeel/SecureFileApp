#  SecureFileApp  

A secure file encryption application consisting of:  
- **Python Desktop Application** 
- **iOS SwiftUI Prototype** 

This project demonstrates how strong cryptography can be combined with usability for handling sensitive files securely.  

---

## Features
- AES-GCM encryption & decryption 
- RSA key wrapping/unwrapping for secure key storage (Keychain on iOS)  
- Cross-platform prototype: Python desktop + iOS app  
- iOS app includes:
  - File picker integration  
  - Encryption & decryption workflow  
  - Preview decrypted text files  
  - Export/share decrypted files  
  - Basic authentication screen (username + password)  

---

## Project Structure
```
SecureFileApp/
│── python-desktop/          # Python implementation
│   └── README.md
│
│── ios-prototype/           # iOS SwiftUI prototype
│   └── README.md
│
└── README.md                # Main documentation
```

---

##  Security Notes
- AES-GCM for file encryption.  
- RSA for key wrapping/unwrapping.  
- iOS app stores keys securely in **Keychain**.  
-  Credentials (`nabeel / Nabeel@123`) are **hardcoded for prototype use only**.  

---

##  Author
Developed by **Muhammed Nabeel**  
For dissertation project – 2025  
