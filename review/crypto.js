import {
  APP_PIN_MAX_LENGTH,
  APP_PIN_MIN_LENGTH,
  LEGACY_PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS
} from "./config.js";

function toBase64(bytes) {
  let text = "";
  for (let index = 0; index < bytes.length; index += 1) {
    text += String.fromCharCode(bytes[index]);
  }
  return btoa(text);
}

function fromBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    out[index] = binary.charCodeAt(index);
  }
  return out;
}

function utf8Encode(text) {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

export function isValidPin(pin) {
  return (
    typeof pin === "string" &&
    new RegExp(`^\\d{${APP_PIN_MIN_LENGTH},${APP_PIN_MAX_LENGTH}}$`).test(pin.trim())
  );
}

export function generateRandomHex(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function deriveKey(pin, salt, iterations = PBKDF2_ITERATIONS) {
  const material = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(utf8Encode(pin)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      iterations
    },
    material,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptJson(secretObject, pin) {
  if (!isValidPin(pin)) {
    throw new Error("PIN 6 ile 12 hane arasinda olmali.");
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pin.trim(), salt);
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv)
    },
    key,
    toArrayBuffer(utf8Encode(JSON.stringify(secretObject)))
  );

  return {
    version: 2,
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    cipher: toBase64(new Uint8Array(cipherBuffer))
  };
}

export async function decryptJson(payload, pin) {
  if (!isValidPin(pin)) {
    throw new Error("PIN 6 ile 12 hane arasinda olmali.");
  }

  try {
    const salt = fromBase64(payload.salt);
    const iv = fromBase64(payload.iv);
    const cipher = fromBase64(payload.cipher);
    const iterations = Number(payload?.iterations ?? LEGACY_PBKDF2_ITERATIONS);
    const key = await deriveKey(pin.trim(), salt, iterations);
    const plainBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv)
      },
      key,
      toArrayBuffer(cipher)
    );
    return JSON.parse(utf8Decode(new Uint8Array(plainBuffer)));
  } catch {
    throw new Error("PIN hatali veya cüzdan verisi bozuk.");
  }
}
