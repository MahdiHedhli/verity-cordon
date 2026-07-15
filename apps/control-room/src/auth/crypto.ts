import type { ControlRoomChallenge } from "../api/types";

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function deriveChallengeProof(
  passphrase: string,
  challenge: ControlRoomChallenge,
): Promise<string> {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const salt = decodeBase64Url(challenge.salt);
  const nonce = decodeBase64Url(challenge.nonce);

  try {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      passphraseBytes,
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const verifier = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: challenge.iterations,
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign("HMAC", verifier, nonce);
    return encodeBase64Url(signature);
  } finally {
    passphraseBytes.fill(0);
    nonce.fill(0);
  }
}
