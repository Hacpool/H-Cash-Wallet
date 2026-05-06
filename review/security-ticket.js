import { HCASH_SECURITY_TICKET_PUBLIC_KEY_PEM, STORAGE_KEYS } from "./config.js";
import { getSession, setSession } from "./storage.js";

let verifyKeyPromise = null;

function normalizeHex(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^0x/, "");
}

function normalizeTicketOrigin(value) {
  const normalized = String(value || "").trim().replace(/\/+$/, "");

  if (!normalized) {
    return "";
  }

  try {
    const parsed = new URL(normalized);
    const protocol = String(parsed.protocol || "").trim().toLowerCase();
    const hostname = String(parsed.hostname || "").trim().toLowerCase();
    const port = String(parsed.port || "").trim();
    const normalizedHost =
      hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]"
        ? "localhost"
        : hostname;

    return `${protocol}//${normalizedHost}${port ? `:${port}` : ""}`;
  } catch {
    return normalized.toLowerCase();
  }
}

function canonicalizeValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeValue(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalizeValue(nested)])
    );
  }

  return value;
}

function serializeClaims(claims) {
  return JSON.stringify(canonicalizeValue(claims));
}

function pemToArrayBuffer(pem) {
  const normalized = String(pem || "")
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

function base64UrlToUint8Array(value) {
  const normalized = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(value || "").length / 4) * 4, "=");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function trimLeadingZeroes(bytes) {
  let start = 0;

  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }

  return bytes.slice(start);
}

function derEcdsaSignatureToP1363(bytes, componentSize = 32) {
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);

  if (input.length < 8 || input[0] !== 0x30) {
    return null;
  }

  let offset = 1;
  let sequenceLength = input[offset];
  offset += 1;

  if (sequenceLength & 0x80) {
    const lengthBytes = sequenceLength & 0x7f;
    if (lengthBytes < 1 || lengthBytes > 2 || offset + lengthBytes > input.length) {
      return null;
    }

    sequenceLength = 0;
    for (let index = 0; index < lengthBytes; index += 1) {
      sequenceLength = (sequenceLength << 8) | input[offset + index];
    }
    offset += lengthBytes;
  }

  if (offset + sequenceLength > input.length || input[offset] !== 0x02) {
    return null;
  }

  offset += 1;
  const rLength = input[offset];
  offset += 1;
  if (offset + rLength > input.length || input[offset + rLength] !== 0x02) {
    return null;
  }

  const rBytes = trimLeadingZeroes(input.slice(offset, offset + rLength));
  offset += rLength + 1;
  const sLength = input[offset];
  offset += 1;

  if (offset + sLength > input.length) {
    return null;
  }

  const sBytes = trimLeadingZeroes(input.slice(offset, offset + sLength));
  if (rBytes.length > componentSize || sBytes.length > componentSize) {
    return null;
  }

  const output = new Uint8Array(componentSize * 2);
  output.set(rBytes, componentSize - rBytes.length);
  output.set(sBytes, output.length - sBytes.length);
  return output;
}

async function getVerifyKey() {
  if (!verifyKeyPromise) {
    verifyKeyPromise = crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(HCASH_SECURITY_TICKET_PUBLIC_KEY_PEM),
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      false,
      ["verify"]
    );
  }

  return verifyKeyPromise;
}

async function verifyTicketSignature(ticket) {
  const verifyKey = await getVerifyKey();
  const claims = ticket?.claims;
  const signatureBytes = base64UrlToUint8Array(ticket?.signature);
  const payloadBytes = new TextEncoder().encode(serializeClaims(claims));

  let valid = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    verifyKey,
    signatureBytes,
    payloadBytes
  );

  if (!valid) {
    const convertedSignature = derEcdsaSignatureToP1363(signatureBytes);

    if (convertedSignature) {
      valid = await crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: "SHA-256"
        },
        verifyKey,
        convertedSignature,
        payloadBytes
      );
    }
  }

  if (!valid) {
    throw new Error("Guvenlik bileti imzasi dogrulanamadi.");
  }
}

function cleanupConsumedTickets(rawState) {
  const now = Date.now();
  const normalizedState =
    rawState && typeof rawState === "object" && !Array.isArray(rawState) ? rawState : {};
  const nextState = {};

  for (const [ticketId, expiresAt] of Object.entries(normalizedState)) {
    const expiresAtMs = Date.parse(String(expiresAt || "").trim());
    if (Number.isFinite(expiresAtMs) && expiresAtMs > now) {
      nextState[ticketId] = String(expiresAt).trim();
    }
  }

  return nextState;
}

async function consumeSecurityTicket(ticket) {
  const ticketId = String(ticket?.claims?.ticketId || "").trim();
  const expiresAt = String(ticket?.claims?.expiresAt || "").trim();

  if (!ticketId || !expiresAt) {
    throw new Error("Guvenlik bileti kimligi eksik.");
  }

  const currentState = cleanupConsumedTickets(
    await getSession(STORAGE_KEYS.securityTicketState, {})
  );

  if (currentState[ticketId]) {
    throw new Error("Bu guvenlik bileti daha once kullanildi.");
  }

  currentState[ticketId] = expiresAt;
  await setSession(STORAGE_KEYS.securityTicketState, currentState);
}

function assertCommonTicketClaims(claims, expectedKind, origin, address) {
  if (!claims || claims.kind !== expectedKind) {
    throw new Error("Guvenlik bileti tipi gecersiz.");
  }

  if (normalizeTicketOrigin(claims.origin) !== normalizeTicketOrigin(origin)) {
    throw new Error("Guvenlik bileti origin bilgisi eslesmedi.");
  }

  if (String(claims.address || "").trim() !== String(address || "").trim()) {
    throw new Error("Guvenlik bileti adres bilgisi eslesmedi.");
  }

  const expiresAtMs = Date.parse(String(claims.expiresAt || "").trim());
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error("Guvenlik bileti zamani doldu.");
  }
}

export async function verifyWalletSessionProofTicket({
  origin,
  payload
}) {
  const ticket = payload?.ticket;
  if (!ticket?.claims || !ticket?.signature) {
    throw new Error("Session proof guvenlik bileti eksik.");
  }

  await verifyTicketSignature(ticket);
  assertCommonTicketClaims(
    ticket.claims,
    "wallet-session-proof",
    origin,
    String(payload?.address || "").trim()
  );

  if (normalizeHex(ticket.claims.txBodyHex) !== normalizeHex(payload?.txBodyHex)) {
    throw new Error("Session proof tx body guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.signHash) !== normalizeHex(payload?.signHash)) {
    throw new Error("Session proof sign hash guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.hashWithFee) !== normalizeHex(payload?.hashWithFee)) {
    throw new Error("Session proof hash_with_fee guvenlik bileti ile eslesmedi.");
  }

  await consumeSecurityTicket(ticket);
}

function normalizeAmount(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return String(value ?? "").trim();
  }

  return numeric.toFixed(3).replace(/\.?0+$/, "");
}

export async function verifyNativeBidAuthorizationTicket({
  origin,
  payload
}) {
  const ticket = payload?.authorizationTicket;
  if (!ticket?.claims || !ticket?.signature) {
    throw new Error("Native bid guvenlik bileti eksik.");
  }

  await verifyTicketSignature(ticket);
  assertCommonTicketClaims(
    ticket.claims,
    "hcash-native-bid",
    origin,
    String(payload?.bidderAddress || "").trim()
  );

  if (String(ticket.claims.diamondName || "").trim() !== String(payload?.diamondName || "").trim()) {
    throw new Error("Native bid diamond bilgisi guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.currentTxHash) !== normalizeHex(payload?.currentTxHash)) {
    throw new Error("Native bid current tx hash guvenlik bileti ile eslesmedi.");
  }

  if (
    normalizeHex(ticket.claims.existingBidTxHash) !==
    normalizeHex(payload?.existingBidTxHash || "")
  ) {
    throw new Error("Native bid onceki tx hash guvenlik bileti ile eslesmedi.");
  }

  if (normalizeAmount(ticket.claims.requestedBidAmount) !== normalizeAmount(payload?.requestedBidAmount)) {
    throw new Error("Native bid teklif tutari guvenlik bileti ile eslesmedi.");
  }

  if (normalizeAmount(ticket.claims.feeAmount) !== normalizeAmount(payload?.feeAmount)) {
    throw new Error("Native bid fee tutari guvenlik bileti ile eslesmedi.");
  }

  if (String(ticket.claims.rewardAddress || "").trim() !== String(payload?.rewardAddress || "").trim()) {
    throw new Error("Native bid reward adresi guvenlik bileti ile eslesmedi.");
  }

  if (String(ticket.claims.mode || "").trim() !== String(payload?.mode || "").trim()) {
    throw new Error("Native bid modu guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.sourceTxHash) !== normalizeHex(payload?.sourceTxHash)) {
    throw new Error("Native bid source tx hash guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.bidTxBodyHex) !== normalizeHex(payload?.bidTxBodyHex)) {
    throw new Error("Native bid tx body guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.bidHashWithFee) !== normalizeHex(payload?.bidHashWithFee)) {
    throw new Error("Native bid hash_with_fee guvenlik bileti ile eslesmedi.");
  }

  if (normalizeHex(ticket.claims.bidSignHash) !== normalizeHex(payload?.bidSignHash)) {
    throw new Error("Native bid sign hash guvenlik bileti ile eslesmedi.");
  }

  await consumeSecurityTicket(ticket);
}
