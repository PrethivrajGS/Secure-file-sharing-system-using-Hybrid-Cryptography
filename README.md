# 🔐 Secure File Sharing System (SFS)

A high-security, browser-based file encryption tool implementing **Hybrid Cryptography**. This system allows users to exchange files securely over insecure channels without ever sending plaintext data or private keys to a server.

![License](https://img.shields.io/badge/license-MIT-blue)
![Crypto](https://img.shields.io/badge/crypto-Web_Crypto_API-orange)
![Security](https://img.shields.io/badge/security-Zero--Trust-green)

## 🚀 Features
- **Zero-Trust Architecture:** All cryptographic operations happen in the browser. No data is ever uploaded to a server.
- **Hybrid Encryption:** Combines the speed of AES with the key-distribution convenience of RSA.
- **Integrity Protection:** Uses SHA-512 to ensure files are not modified or corrupted during transit.
- **Modern Standards:** Implements AES-GCM (Authenticated Encryption) for built-in tamper detection.

## 🛠️ Technical Stack
| Component | Algorithm | Purpose |
| :--- | :--- | :--- |
| **Integrity** | SHA-512 | Digital fingerprinting of files. |
| **Data Encryption** | AES-GCM-256 | High-speed symmetric encryption. |
| **Key Exchange** | RSA-OAEP-2048 | Asymmetric wrapping of the AES session key. |
| **Implementation** | Web Crypto API | Native, hardware-accelerated browser security. |

## 📦 File Structure
- `index.html`: System dashboard and entry point.
- `keygen.html`: RSA-2048 key pair generator.
- `send.html`: File encryption and bundle creation interface.
- `receive.html`: RSA decryption and integrity verification interface.
- `verify.html`: Standalone SHA-512 utility and avalanche effect demo.
- `crypto-engine.js`: The core cryptographic logic using `window.crypto.subtle`.
- `theme.css`: Industrial terminal aesthetic (dark mode).
- `workflow.html`: Comprehensive technical documentation.

## 📖 Usage Instructions

1. **Generate Keys:** The recipient goes to **Key Gen**, generates a pair, and sends their **Public Key** to the sender.
2. **Encrypt:** The sender goes to **Send File**, selects a file, pastes the recipient's Public Key, and downloads the generated `.json` bundle.
3. **Transfer:** The sender sends the `.json` bundle to the recipient via any platform.
4. **Decrypt:** The recipient goes to **Receive**, loads the bundle and their **Private Key**, and downloads the original file.

## ⚠️ Security Disclaimer
This application is provided for educational and utility purposes. While it uses industry-standard algorithms (RSA-2048, AES-256), the security of the system depends entirely on the security of your local browser environment and the secrecy of your private keys.

## 📜 License
This project is licensed under the MIT License.
