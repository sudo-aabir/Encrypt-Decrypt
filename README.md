# EncryptDecrypt

A browser-based web app for asymmetric encryption/decryption and secure file exchange (images, audio, and any file type).

## Crypto approach
- RSA-OAEP (SHA-256, 2048-bit) encrypts a one-time AES key.
- AES-256-GCM encrypts the actual text/file bytes.
- Everything runs client-side in the browser using Web Crypto API.

## Usage
1. Open `index.html` in a modern browser.
2. Generate RSA keys or paste existing base64 keys.
3. Encrypt/decrypt text.
4. Encrypt/decrypt files via `.enc.json` payloads.

## Optional local server
```bash
python -m http.server 8000
```
Then visit `http://localhost:8000`.

Thank You
