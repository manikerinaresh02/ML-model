# Face Authentication Solution for UIDAI

## High-Level Flow

1.  **User Interaction Start:**
    *   User accesses the UIDAI website and clicks the Face Authentication button.
2.  **Bot Detection:**
    *   CAPTCHA-based human verification is used.
    *   If the user fails (bot detected), access is blocked.
3.  **Model Availability Check:**
    *   If the model is already cached in the browser:
        *   Directly proceed to use it for liveness/anti-spoofing check.
    *   If not cached:
        *   Secure model download process is triggered.
4.  **Secure Model Download Process:**
    *   AES encryption is used on the server to protect the model.
    *   Passkey (decryption key) is sent securely using ECC (Elliptic Curve Cryptography) over a TLS connection.
    *   The user must enter this decryption passkey to download the model.
    *   If correct: model is downloaded and cached.
    *   If incorrect: retry allowed up to 3 times.
5.  **Face Authentication Process:**
    *   ML model (ONNX / Tensorflow.js runtime) performs anti-spoofing/liveness check.
    *   If the face is real: access granted to credentials.
    *   If spoof detected: authentication fails.

## Core Technical Highlights

| Component           | Technique/Tool Used                                  |
| ------------------- | ---------------------------------------------------- |
| Human Verification  | CAPTCHA                                            |
| Model Security      | AES encryption + ECC for key exchange over TLS       |
| Edge Inference      | ML Model runs in browser using ONNX.js / Tensorflow.js |
| Model Caching       | Browser cache (avoids repeated downloads)            |
| Tampering Protection | Encrypted model + passkey protected + TLS            |
| Fallback Mechanism  | 3 attempts allowed to enter correct passkey          |

## Meets UIDAI Requirements

*   **Model Security:**
    *   Encrypted delivery + secure key exchange.
    *   Model isn’t directly exposed or readable.
*   **Model Size Optimization:**
    *   No significant post-security bloat (AES/ECC are lightweight).
*   **Backend Component:**
    *   Handles encryption dynamically (just-in-time or during release).
    *   Scalable for large user volume.

## Suggestions to Improve/Extend

*   **Obfuscation Layer:** Add model structure obfuscation (layer renaming, noise injection) before encryption.
*   **WebAssembly Wrapping:** Load model in a WebAssembly sandbox to further hinder reverse engineering.
*   **Zero-Knowledge Proof:** Use ZKPs for verifying decrypted model integrity before use (advanced).
