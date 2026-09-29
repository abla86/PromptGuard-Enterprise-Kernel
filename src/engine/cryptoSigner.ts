/**
 * PromptGuard Enterprise Kernel - Cryptographic Audit Signer
 * 
 * Provides deterministic RFC 8785 JSON Canonicalization and
 * ECDSA P-256 / SHA-256 asymmetric cryptographic signing and verification
 * using the W3C Web Cryptography API (SubtleCrypto).
 */

export interface SigningKeyPair {
  keyId: string;
  publicKeyPem: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  algorithm: string;
  createdAt: string;
}

export interface SignatureBlock {
  signature_algorithm: 'ECDSA-P256-SHA256';
  key_id: string;
  canonicalization: 'RFC-8785-JCS';
  payload_digest_sha256: string;
  signature_hex: string;
  signature_base64: string;
  public_key_pem: string;
  signed_at: string;
}

export interface VerificationResult {
  isValid: boolean;
  algorithm: string;
  keyId: string;
  signedAt: string;
  digestMatch: boolean;
  computedDigestSha256: string;
  reportDigestSha256: string;
  error?: string;
}

/**
 * Deterministic JSON Canonicalization (RFC 8785 subset)
 * Sorts object keys recursively to ensure bit-level deterministic string output.
 */
export function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => canonicalizeJson(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((key) => {
    return JSON.stringify(key) + ':' + canonicalizeJson(obj[key]);
  });

  return '{' + pairs.join(',') + '}';
}

/**
 * ArrayBuffer to Hex string conversion
 */
export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * ArrayBuffer to Base64 string conversion
 */
export function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Base64 string to Uint8Array conversion
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts an SPKI CryptoKey into PEM format
 */
export async function exportPublicKeyToPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', key);
  const base64 = bufferToBase64(exported);
  const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join('\n') || base64}\n-----END PUBLIC KEY-----`;
  return pem;
}

/**
 * Imports an SPKI PEM string into a CryptoKey for verification
 */
export async function importPublicKeyFromPem(pem: string): Promise<CryptoKey> {
  const cleanedPem = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\s+/g, '');
  const keyBuffer = base64ToUint8Array(cleanedPem);

  return await crypto.subtle.importKey(
    'spki',
    keyBuffer.buffer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['verify']
  );
}

/**
 * Compute SHA-256 hash of a string
 */
export async function computeSha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

// Global cached session key pair for consistent session signing
let sessionKeyPairCache: SigningKeyPair | null = null;

/**
 * Generates or retrieves the active session's ECDSA P-256 key pair
 */
export async function getOrCreateSessionKeyPair(): Promise<SigningKeyPair> {
  if (sessionKeyPairCache) {
    return sessionKeyPairCache;
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  const randBytes = new Uint8Array(4);
  crypto.getRandomValues(randBytes);
  const keySuffix = Array.from(randBytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const keyId = `PG-KEY-P256-${keySuffix}`;

  const publicKeyPem = await exportPublicKeyToPem(keyPair.publicKey);

  sessionKeyPairCache = {
    keyId,
    publicKeyPem,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    algorithm: 'ECDSA-P256-SHA256',
    createdAt: new Date().toISOString(),
  };

  return sessionKeyPairCache;
}

/**
 * Signs an audit report payload deterministically
 */
export async function signAuditReport(
  reportDataWithoutSignature: Record<string, any>,
  customKeyPair?: SigningKeyPair
): Promise<{ signedReport: any; signatureBlock: SignatureBlock }> {
  const keyPair = customKeyPair || (await getOrCreateSessionKeyPair());

  // 1. Create canonical JSON representation of the report content
  const canonicalString = canonicalizeJson(reportDataWithoutSignature);

  // 2. Compute SHA-256 digest of canonical data
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(canonicalString);
  const digestBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const payloadDigestSha256 = bufferToHex(digestBuffer);

  // 3. Sign the canonical buffer using ECDSA P-256 with SHA-256
  const signatureBuffer = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    keyPair.privateKey,
    dataBuffer
  );

  const signatureHex = bufferToHex(signatureBuffer);
  const signatureBase64 = bufferToBase64(signatureBuffer);

  const signatureBlock: SignatureBlock = {
    signature_algorithm: 'ECDSA-P256-SHA256',
    key_id: keyPair.keyId,
    canonicalization: 'RFC-8785-JCS',
    payload_digest_sha256: payloadDigestSha256,
    signature_hex: signatureHex,
    signature_base64: signatureBase64,
    public_key_pem: keyPair.publicKeyPem,
    signed_at: new Date().toISOString(),
  };

  const signedReport = {
    ...reportDataWithoutSignature,
    integrity_and_signature: signatureBlock,
  };

  return {
    signedReport,
    signatureBlock,
  };
}

/**
 * Cryptographically verifies an exported audit report JSON
 */
export async function verifyAuditReportJson(report: any): Promise<VerificationResult> {
  try {
    if (!report || typeof report !== 'object') {
      return {
        isValid: false,
        algorithm: 'UNKNOWN',
        keyId: 'NONE',
        signedAt: '',
        digestMatch: false,
        computedDigestSha256: '',
        reportDigestSha256: '',
        error: 'Invalid report: root payload must be a JSON object.',
      };
    }

    const signatureBlock: SignatureBlock = report.integrity_and_signature;
    if (!signatureBlock) {
      return {
        isValid: false,
        algorithm: 'UNKNOWN',
        keyId: 'NONE',
        signedAt: '',
        digestMatch: false,
        computedDigestSha256: '',
        reportDigestSha256: '',
        error: 'Missing integrity_and_signature block in audit report.',
      };
    }

    if (signatureBlock.signature_algorithm !== 'ECDSA-P256-SHA256') {
      return {
        isValid: false,
        algorithm: signatureBlock.signature_algorithm,
        keyId: signatureBlock.key_id,
        signedAt: signatureBlock.signed_at,
        digestMatch: false,
        computedDigestSha256: '',
        reportDigestSha256: signatureBlock.payload_digest_sha256 || '',
        error: `Unsupported signature algorithm: ${signatureBlock.signature_algorithm}`,
      };
    }

    // Clone report and strip the signature block to recover canonical target
    const reportDataWithoutSig = { ...report };
    delete reportDataWithoutSig.integrity_and_signature;

    const canonicalString = canonicalizeJson(reportDataWithoutSig);
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(canonicalString);

    // Recompute payload digest
    const digestBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const computedDigestSha256 = bufferToHex(digestBuffer);
    const digestMatch = computedDigestSha256 === signatureBlock.payload_digest_sha256;

    // Import public key
    const publicKey = await importPublicKeyFromPem(signatureBlock.public_key_pem);

    // Verify ECDSA signature
    const signatureBytes = base64ToUint8Array(signatureBlock.signature_base64);
    const isValidSignature = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signatureBytes.buffer,
      dataBuffer
    );

    return {
      isValid: isValidSignature && digestMatch,
      algorithm: signatureBlock.signature_algorithm,
      keyId: signatureBlock.key_id,
      signedAt: signatureBlock.signed_at,
      digestMatch,
      computedDigestSha256,
      reportDigestSha256: signatureBlock.payload_digest_sha256,
      error: !digestMatch
        ? 'Payload hash mismatch: report data has been tampered with or modified after signing.'
        : !isValidSignature
        ? 'Cryptographic signature is invalid for the provided public key.'
        : undefined,
    };
  } catch (err: any) {
    return {
      isValid: false,
      algorithm: 'ERROR',
      keyId: 'ERROR',
      signedAt: '',
      digestMatch: false,
      computedDigestSha256: '',
      reportDigestSha256: '',
      error: `Verification exception: ${err?.message || 'Unknown error parsing report'}`,
    };
  }
}
