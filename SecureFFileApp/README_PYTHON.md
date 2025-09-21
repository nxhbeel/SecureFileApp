# SecureFileApp – Python Desktop Version  

This is the **Python implementation** of the SecureFileApp project.  
It provides AES-GCM file encryption and decryption with a simple command-line or GUI-based interface.  

---

##  Requirements
- Python 3.9+  

Install dependencies:  
```bash
pip install -r requirements.txt
```

---

##  Run
To start the application:  
```bash
cd desktop/SecureFileApp/python-desktop
python3 main_gui.py
```

---

##  Security
- Uses AES-GCM for file encryption/decryption.  
- Files are encrypted with a Data Encryption Key (DEK).  
- RSA is used to wrap/unwrap the DEK (proof-of-concept).  

---

##  Notes
- Designed as a **prototype for cross-platform secure file handling**.  
- Intended to demonstrate **integration with iOS counterpart**.  
