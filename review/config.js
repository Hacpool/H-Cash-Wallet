export const WALLET_NAME = "H-Cash Wallet";
export const WALLET_VERSION = "0.3.3";
export const SESSION_TTL_MS = 1 * 60 * 60 * 1000;
export const AUTO_BID_SESSION_BUFFER_HOURS = 1;
export const AUTO_BID_SESSION_MAX_HOURS = 12;
export const SENSITIVE_REVEAL_TTL_MS = 45 * 1000;
export const LEGACY_PBKDF2_ITERATIONS = 320_000;
export const PBKDF2_ITERATIONS = 900_000;
export const APP_PIN_MIN_LENGTH = 6;
export const APP_PIN_MAX_LENGTH = 12;
export const REQUEST_TIMEOUT_MS = 3 * 60 * 1000;
export const PIN_LOCKOUT_THRESHOLD = 5;
export const PIN_LOCKOUT_MAX_MS = 24 * 60 * 60 * 1000;

const PRODUCTION_SITE_ORIGINS = new Set([
  "https://hacpool.xyz",
  "https://www.hacpool.xyz"
]);

const DEVELOPMENT_SITE_ORIGINS = new Set([
  "http://127.0.0.1:45173",
  "http://localhost:45173",
  "http://127.0.0.1:3999",
  "http://localhost:3999"
]);

function isChromeWebStoreInstall() {
  try {
    return Boolean(chrome?.runtime?.getManifest?.().update_url);
  } catch {
    return false;
  }
}

export function isAllowedSiteOrigin(origin = "") {
  const normalizedOrigin = String(origin || "").trim().replace(/\/+$/, "");

  if (PRODUCTION_SITE_ORIGINS.has(normalizedOrigin)) {
    return true;
  }

  if (DEVELOPMENT_SITE_ORIGINS.has(normalizedOrigin)) {
    return !isChromeWebStoreInstall();
  }

  return false;
}

export function getAllowedSiteOrigins() {
  const origins = [...PRODUCTION_SITE_ORIGINS];

  if (!isChromeWebStoreInstall()) {
    origins.push(...DEVELOPMENT_SITE_ORIGINS);
  }

  return origins;
}

export const ALLOWED_SITE_ORIGINS = new Set(getAllowedSiteOrigins());

export const SECURE_WALLET_API_BASE_URL = "https://hacpool.xyz/api/hacash-wallet";
export const OFFICIAL_HACASH_NODE_API_BASE_URL = "http://nodeapi.hacash.org";
export const DEFAULT_EXPLORER_URL = "https://explorer.hacash.org";
export const HCASH_SECURITY_TICKET_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWTtDj3XogwPy05YLyIjcqm+Z27OX
NV0imHMkOfegdurv8F9Dw0hKG6E9/DugPQ+gZJeXz/vNm1GC2UZPEMakYw==
-----END PUBLIC KEY-----`;

export function resolveWalletApiBaseUrl(origin = "") {
  const normalizedOrigin = String(origin || "").trim().replace(/\/+$/, "");

  if (
    normalizedOrigin === "http://127.0.0.1:45173" ||
    normalizedOrigin === "http://localhost:45173" ||
    normalizedOrigin === "http://127.0.0.1:3999" ||
    normalizedOrigin === "http://localhost:3999"
  ) {
    return `${normalizedOrigin}/api/hacash-wallet`;
  }

  return SECURE_WALLET_API_BASE_URL;
}

export const STORAGE_KEYS = {
  walletRecord: "hacpool_wallet_record_v1",
  addressBook: "hacpool_wallet_address_book_v1",
  approvedOrigins: "hacpool_wallet_approved_origins_v1",
  reserveLedger: "hacpool_wallet_reserve_ledger_v1",
  transactionLog: "hacpool_wallet_transaction_log_v1",
  settings: "hacpool_wallet_settings_v1",
  securityState: "hacpool_wallet_security_state_v1",
  securityTicketState: "hacpool_wallet_security_ticket_state_v1",
  session: "hacpool_wallet_session_v1",
  signingCache: "hacpool_wallet_signing_cache_v1"
};

export const VENDOR_SDK_PATH = {
  script: "vendor/hacash-sdk/hacash_sdk.js",
  wasm: "vendor/hacash-sdk/hacash_sdk.wasm"
};
