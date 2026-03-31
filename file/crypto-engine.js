/**
 * ============================================================
 *  SECURE FILE SHARING SYSTEM — Crypto Engine
 *  Algorithms: SHA-512 · AES-GCM-256 · RSA-OAEP-2048
 *  All operations run in-browser via Web Crypto API.
 *  No keys or file data ever leave the device.
 * ============================================================
 */

"use strict";

const CryptoEngine = (() => {

  // ── Utility Helpers ──────────────────────────────────────

  /** Convert ArrayBuffer → hex string */
  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /** Convert ArrayBuffer → Base64 string */
  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  /** Convert Base64 string → Uint8Array */
  function b64ToBuf(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  /** Encode string to Uint8Array */
  function strToBytes(str) {
    return new TextEncoder().encode(str);
  }

  /** Decode Uint8Array to string */
  function bytesToStr(buf) {
    return new TextDecoder().decode(buf);
  }

  /** Export CryptoKey to PEM format */
  async function keyToPem(key, type) {
    const fmt = type === "public" ? "spki" : "pkcs8";
    const exported = await crypto.subtle.exportKey(fmt, key);
    const b64 = bufToB64(exported);
    const label = type === "public" ? "PUBLIC KEY" : "PRIVATE KEY";
    const body = b64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
  }

  /** Import RSA public key from PEM */
  async function pemToPublicKey(pem) {
    const b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s/g, "");
    const buf = b64ToBuf(b64);
    return crypto.subtle.importKey(
      "spki", buf,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true, ["encrypt"]
    );
  }

  /** Import RSA private key from PEM */
  async function pemToPrivateKey(pem) {
    const b64 = pem
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\s/g, "");
    const buf = b64ToBuf(b64);
    return crypto.subtle.importKey(
      "pkcs8", buf,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true, ["decrypt"]
    );
  }

  // ── MODULE 1: SHA-512 File Integrity ─────────────────────

  /**
   * Compute SHA-512 hash of a File or ArrayBuffer.
   * Returns: { hex, b64, size, algorithm }
   */
  async function hashFile(fileOrBuffer) {
    let buf;
    if (fileOrBuffer instanceof ArrayBuffer) {
      buf = fileOrBuffer;
    } else {
      buf = await fileOrBuffer.arrayBuffer();
    }
    const hashBuf = await crypto.subtle.digest("SHA-512", buf);
    return {
      hex: bufToHex(hashBuf),
      b64: bufToB64(hashBuf),
      bits: 512,
      algorithm: "SHA-512",
      fileSize: buf.byteLength
    };
  }

  /**
   * Verify a file against a known SHA-512 hex digest.
   * Returns: { valid, computed, expected }
   */
  async function verifyFileHash(fileOrBuffer, expectedHex) {
    const result = await hashFile(fileOrBuffer);
    return {
      valid: result.hex.toLowerCase() === expectedHex.toLowerCase(),
      computed: result.hex,
      expected: expectedHex
    };
  }

  // ── MODULE 2: AES-GCM File Encryption ────────────────────

  /**
   * Encrypt a File with AES-GCM-256.
   * Returns: { encryptedB64, keyB64, ivB64, saltB64, sha512hex, fileName, fileType, fileSize }
   * 
   * Workflow:
   *  1. Read file bytes
   *  2. Compute SHA-512 of original file (for integrity)
   *  3. Generate random 256-bit AES key + 96-bit IV + 128-bit salt
   *  4. Encrypt with AES-GCM (appends 128-bit auth tag)
   *  5. Bundle everything into a JSON envelope
   */
  async function encryptFile(file) {
    // Step 1 — Read file
    const fileBuf = await file.arrayBuffer();

    // Step 2 — Hash original file with SHA-512
    const hashResult = await hashFile(fileBuf);

    // Step 3 — Generate AES-256 key, 96-bit IV, 128-bit salt
    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Step 4 — Encrypt
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, aesKey, fileBuf
    );

    // Step 5 — Export key material
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);

    return {
      encryptedB64: bufToB64(encrypted),
      keyB64:       bufToB64(rawKey),
      ivB64:        bufToB64(iv),
      saltB64:      bufToB64(salt),
      sha512hex:    hashResult.hex,
      fileName:     file.name,
      fileType:     file.type || "application/octet-stream",
      fileSize:     file.size,
      algorithm:    "AES-GCM-256",
      timestamp:    new Date().toISOString()
    };
  }

  /**
   * Decrypt an AES-GCM encrypted bundle.
   * Returns: { fileBytes, sha512hex, fileName, fileType, integrityOk }
   */
  async function decryptFile(bundle) {
    const { encryptedB64, keyB64, ivB64, sha512hex, fileName, fileType } = bundle;

    // Import AES key from raw bytes
    const rawKey = b64ToBuf(keyB64);
    const aesKey = await crypto.subtle.importKey(
      "raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]
    );

    const iv        = b64ToBuf(ivB64);
    const encrypted = b64ToBuf(encryptedB64);

    // Decrypt — throws if auth tag fails
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv }, aesKey, encrypted
    );

    // Verify SHA-512 integrity
    const verifyResult = await verifyFileHash(decrypted, sha512hex);

    return {
      fileBytes:   new Uint8Array(decrypted),
      sha512hex:   (await hashFile(decrypted)).hex,
      fileName,
      fileType,
      integrityOk: verifyResult.valid
    };
  }

  // ── MODULE 3: RSA Key Wrapping ────────────────────────────

  /**
   * Generate RSA-2048 key pair for key wrapping.
   * Returns: { publicKey, privateKey, publicPem, privatePem }
   */
  async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
    return {
      publicKey:  keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicPem:  await keyToPem(keyPair.publicKey,  "public"),
      privatePem: await keyToPem(keyPair.privateKey, "private")
    };
  }

  /**
   * SENDER SIDE:
   * Wrap (encrypt) the AES session key with RSA-OAEP public key.
   * Returns Base64 string of the RSA-encrypted AES key.
   */
  async function wrapAESKeyWithRSA(aesKeyB64, recipientPublicKey) {
    const rawKey   = b64ToBuf(aesKeyB64);
    const wrapped  = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" }, recipientPublicKey, rawKey
    );
    return bufToB64(wrapped);
  }

  /**
   * RECEIVER SIDE:
   * Unwrap (decrypt) the RSA-encrypted AES key with RSA private key.
   * Returns Base64 string of the recovered AES key.
   */
  async function unwrapAESKeyWithRSA(wrappedKeyB64, recipientPrivateKey) {
    const wrapped  = b64ToBuf(wrappedKeyB64);
    const rawKey   = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" }, recipientPrivateKey, wrapped
    );
    return bufToB64(rawKey);
  }

  // ── MODULE 4: Full Secure Bundle (Hybrid Encryption) ─────

  /**
   * FULL SEND FLOW — used by sender:
   *  1. Hash file with SHA-512
   *  2. Encrypt file with AES-GCM-256 (random key)
   *  3. Wrap AES key with recipient's RSA-2048 public key
   *  4. Return a self-contained secure bundle (JSON)
   *
   * @param {File} file
   * @param {CryptoKey|string} recipientPublicKey - CryptoKey object or PEM string
   */
  async function createSecureBundle(file, recipientPublicKey) {
    // Accept PEM string too
    if (typeof recipientPublicKey === "string") {
      recipientPublicKey = await pemToPublicKey(recipientPublicKey);
    }

    // Step 1+2: encrypt file (includes SHA-512 inside)
    const encrypted = await encryptFile(file);

    // Step 3: wrap AES key with RSA
    const wrappedKey = await wrapAESKeyWithRSA(encrypted.keyB64, recipientPublicKey);

    // Step 4: build secure bundle — remove plain AES key for security
    const bundle = {
      version:       "SFS-v1.0",
      algorithm:     "SHA-512 + AES-GCM-256 + RSA-OAEP-2048",
      wrappedKeyB64: wrappedKey,      // RSA-encrypted AES key
      ivB64:         encrypted.ivB64,
      saltB64:       encrypted.saltB64,
      encryptedB64:  encrypted.encryptedB64,
      sha512hex:     encrypted.sha512hex,
      fileName:      encrypted.fileName,
      fileType:      encrypted.fileType,
      fileSize:      encrypted.fileSize,
      timestamp:     encrypted.timestamp
      // NOTE: keyB64 is NOT included — only the wrapped version
    };

    return {
      bundle,
      bundleJSON:  JSON.stringify(bundle, null, 2),
      sha512hex:   encrypted.sha512hex,
      fileSize:    encrypted.fileSize,
      fileName:    encrypted.fileName
    };
  }

  /**
   * FULL RECEIVE FLOW — used by recipient:
   *  1. Unwrap AES key using RSA private key
   *  2. Decrypt file using recovered AES key
   *  3. Verify SHA-512 integrity of decrypted file
   *  4. Return file bytes + integrity status
   *
   * @param {object|string} bundle - bundle object or JSON string
   * @param {CryptoKey|string} recipientPrivateKey - CryptoKey object or PEM string
   */
  async function openSecureBundle(bundle, recipientPrivateKey) {
    if (typeof bundle === "string") bundle = JSON.parse(bundle);
    if (typeof recipientPrivateKey === "string") {
      recipientPrivateKey = await pemToPrivateKey(recipientPrivateKey);
    }

    // Step 1: unwrap AES key
    const keyB64 = await unwrapAESKeyWithRSA(bundle.wrappedKeyB64, recipientPrivateKey);

    // Step 2+3: decrypt and verify
    const decryptResult = await decryptFile({
      encryptedB64: bundle.encryptedB64,
      keyB64,
      ivB64:        bundle.ivB64,
      sha512hex:    bundle.sha512hex,
      fileName:     bundle.fileName,
      fileType:     bundle.fileType
    });

    return {
      fileBytes:   decryptResult.fileBytes,
      fileName:    decryptResult.fileName,
      fileType:    decryptResult.fileType,
      sha512hex:   decryptResult.sha512hex,
      integrityOk: decryptResult.integrityOk,
      originalHash: bundle.sha512hex
    };
  }

  // ── Public API ────────────────────────────────────────────

  return {
    // Utilities
    bufToHex, bufToB64, b64ToBuf, strToBytes, bytesToStr, keyToPem,
    pemToPublicKey, pemToPrivateKey,

    // SHA-512 Integrity
    hashFile,
    verifyFileHash,

    // AES-GCM File Encryption
    encryptFile,
    decryptFile,

    // RSA Key Wrapping
    generateRSAKeyPair,
    wrapAESKeyWithRSA,
    unwrapAESKeyWithRSA,

    // Full Hybrid Workflow
    createSecureBundle,
    openSecureBundle
  };
})();

// Make available globally
window.CryptoEngine = CryptoEngine;
