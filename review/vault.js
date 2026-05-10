import {
  isAllowedSiteOrigin,
  SESSION_TTL_MS,
  STORAGE_KEYS,
  WALLET_NAME
} from "./config.js";
import { decryptJson, encryptJson, isValidPin } from "./crypto.js";
import { deriveAccountFromPrivateKey, createWalletFromRandomSeed, signTxHash } from "./hacash-sdk.js";
import {
  assertPinEntryAllowed,
  notePinFailure,
  notePinSuccess
} from "./pin-security.js";
import {
  getLocal,
  getSession,
  removeLocal,
  removeSession,
  setLocal,
  setSession
} from "./storage.js";

let legacySigningCachePurged = false;

function resolveSessionExpiryMs(session) {
  const explicitExpiryMs = Number(session?.expiresAt);
  if (Number.isFinite(explicitExpiryMs) && explicitExpiryMs > 0) {
    return explicitExpiryMs;
  }

  const unlockedAtMs = Number(session?.unlockedAt);
  if (!Number.isFinite(unlockedAtMs) || unlockedAtMs <= 0) {
    return null;
  }

  return unlockedAtMs + SESSION_TTL_MS;
}

function sessionExpired(session) {
  const expiryMs = resolveSessionExpiryMs(session);
  if (!Number.isFinite(expiryMs)) {
    return true;
  }

  return Date.now() >= Number(expiryMs);
}

function createEmptyWalletStore() {
  return {
    wallets: [],
    activeAddress: ""
  };
}

function normalizeWalletStore(rawStore) {
  if (!rawStore) {
    return createEmptyWalletStore();
  }

  if (Array.isArray(rawStore.wallets)) {
    const wallets = rawStore.wallets
      .filter((item) => item?.address && item?.encryptedSecret)
      .map((item) => ({
        address: String(item.address).trim(),
        encryptedSecret: item.encryptedSecret,
        createdAt: item.createdAt || new Date().toISOString()
      }));

    const activeAddress = wallets.some((item) => item.address === rawStore.activeAddress)
      ? String(rawStore.activeAddress).trim()
      : wallets[0]?.address || "";

    return {
      wallets,
      activeAddress
    };
  }

  if (rawStore.address && rawStore.encryptedSecret) {
    return {
      wallets: [
        {
          address: String(rawStore.address).trim(),
          encryptedSecret: rawStore.encryptedSecret,
          createdAt: rawStore.createdAt || new Date().toISOString()
        }
      ],
      activeAddress: String(rawStore.address).trim()
    };
  }

  return createEmptyWalletStore();
}

async function readWalletStore() {
  await purgeLegacySigningCache();
  const rawStore = await getLocal(STORAGE_KEYS.walletRecord, null);
  return normalizeWalletStore(rawStore);
}

async function purgeLegacySigningCache() {
  if (legacySigningCachePurged) {
    return;
  }

  legacySigningCachePurged = true;
  await Promise.all([
    removeLocal(STORAGE_KEYS.signingCache).catch(() => undefined),
    removeSession(STORAGE_KEYS.signingCache).catch(() => undefined)
  ]);
}

async function writeWalletStore(store) {
  const normalized = normalizeWalletStore(store);
  await setLocal(STORAGE_KEYS.walletRecord, normalized);
  return normalized;
}

async function decryptWalletRecordSecret(walletRecord, pin) {
  await assertPinEntryAllowed();

  try {
    const secret = await decryptJson(walletRecord.encryptedSecret, String(pin || "").trim());
    await notePinSuccess();
    return secret;
  } catch {
    const message = await notePinFailure();
    throw new Error(message);
  }
}

function getWalletRecordByAddress(store, address) {
  return store.wallets.find((item) => item.address === String(address || "").trim()) ?? null;
}

function resolveActiveAddress(store, session) {
  if (store.activeAddress && store.wallets.some((item) => item.address === store.activeAddress)) {
    return store.activeAddress;
  }

  const sessionAddress = String(session?.address || "").trim();
  if (sessionAddress && store.wallets.some((item) => item.address === sessionAddress)) {
    return sessionAddress;
  }

  return store.wallets[0]?.address || "";
}

async function addWalletToStore(account, pin) {
  const store = await readWalletStore();
  if (getWalletRecordByAddress(store, account.address)) {
    throw new Error("Bu cüzdan zaten import edildi.");
  }

  const encrypted = await encryptJson(
    {
      privateKey: account.privateKey
    },
    pin
  );

  store.wallets.push({
    address: account.address,
    encryptedSecret: encrypted,
    createdAt: new Date().toISOString()
  });
  store.activeAddress = account.address;
  await writeWalletStore(store);
  await setSession(STORAGE_KEYS.session, {
    address: account.address,
    privateKey: account.privateKey,
    unlockedAt: Date.now(),
    expiresAt: null
  });

  return store;
}

export async function getVaultState(activeOrigin = null) {
  const [store, session, approvedOrigins] = await Promise.all([
    readWalletStore(),
    getSession(STORAGE_KEYS.session, null),
    getLocal(STORAGE_KEYS.approvedOrigins, [])
  ]);

  const origins = Array.isArray(approvedOrigins) ? approvedOrigins : [];
  let validSession = session && !sessionExpired(session) ? session : null;
  if (session && !validSession) {
    await removeSession(STORAGE_KEYS.session);
  }

  const address = resolveActiveAddress(store, validSession);

  const unlocked = Boolean(validSession);

  return {
    walletName: WALLET_NAME,
    initialized: store.wallets.length > 0,
    address,
    activeAddress: address,
    unlocked,
    approvedOrigins: origins,
    activeOrigin,
    activeOriginApproved: activeOrigin ? origins.includes(activeOrigin) : false,
    wallets: store.wallets.map((item) => ({
      address: item.address,
      createdAt: item.createdAt
    })),
    walletCount: store.wallets.length
  };
}

export async function createWallet(pin) {
  if (!isValidPin(pin)) {
    throw new Error("PIN 6 ile 12 hane arasinda olmali.");
  }

  const account = await createWalletFromRandomSeed();
  await addWalletToStore(account, pin);
  return getVaultState();
}

export async function importWallet(input) {
  const pin = String(input.pin || "").trim();
  const privateKey = String(input.privateKey || "").trim().toLowerCase();
  const providedAddress = String(input.address || "").trim();

  if (!isValidPin(pin)) {
    throw new Error("PIN 6 ile 12 hane arasinda olmali.");
  }

  const account = await deriveAccountFromPrivateKey(privateKey);
  if (providedAddress && providedAddress !== account.address) {
    throw new Error("Girilen adres private key ile eslesmiyor.");
  }

  await addWalletToStore(account, pin);
  return getVaultState();
}

export async function setActiveWallet(address) {
  const store = await readWalletStore();
  const walletRecord = getWalletRecordByAddress(store, address);
  if (!walletRecord) {
    throw new Error("Secilen cüzdan bulunamadi.");
  }

  store.activeAddress = walletRecord.address;
  await writeWalletStore(store);
  return getVaultState();
}

export async function deleteWallet(address) {
  const store = await readWalletStore();
  const safeAddress = String(address || "").trim();
  const nextWallets = store.wallets.filter((item) => item.address !== safeAddress);
  if (nextWallets.length === store.wallets.length) {
    throw new Error("Silinecek cüzdan bulunamadi.");
  }

  const session = await getSession(STORAGE_KEYS.session, null);
  if (String(session?.address || "").trim() === safeAddress) {
    await removeSession(STORAGE_KEYS.session);
  }
  await removeSession(STORAGE_KEYS.signingCache);

  const nextStore = {
    wallets: nextWallets,
    activeAddress:
      store.activeAddress === safeAddress
        ? nextWallets[0]?.address || ""
        : store.activeAddress
  };

  await writeWalletStore(nextStore);
  return getVaultState();
}

export async function exportPrivateKey(pin, address = "") {
  const store = await readWalletStore();
  const targetAddress =
    String(address || "").trim() || store.activeAddress || store.wallets[0]?.address || "";
  const walletRecord = getWalletRecordByAddress(store, targetAddress);

  if (!walletRecord) {
    throw new Error("Private key gosterilecek cüzdan bulunamadi.");
  }

  const secret = await decryptWalletRecordSecret(walletRecord, pin);
  const privateKey = String(secret.privateKey || "").trim().toLowerCase();
  if (!privateKey) {
    throw new Error("Private key okunamadi.");
  }

  return {
    address: walletRecord.address,
    privateKey
  };
}

export async function unlockWallet(pin, address = "") {
  const store = await readWalletStore();
  if (!store.wallets.length) {
    throw new Error("Henüz cüzdan olusturulmamis.");
  }

  const selectedAddress = String(address || "").trim();
  const walletRecord =
    getWalletRecordByAddress(store, selectedAddress || store.activeAddress) ??
    store.wallets[0] ??
    null;

  if (!walletRecord) {
    throw new Error("Cüzdan kaydi bulunamadi.");
  }

  const secret = await decryptWalletRecordSecret(walletRecord, pin);
  const privateKey = String(secret.privateKey || "").trim();
  if (!privateKey) {
    throw new Error("Cuzdan verisi bozuk.");
  }

  await setSession(STORAGE_KEYS.session, {
    address: walletRecord.address,
    privateKey,
    unlockedAt: Date.now(),
    expiresAt: null
  });

  return getVaultState();
}

export async function reauthorizeWallet(pin, address = "") {
  await unlockWallet(pin, address);
  return requireUnlockedSession();
}

export async function lockWallet() {
  await Promise.all([
    removeSession(STORAGE_KEYS.session),
    removeSession(STORAGE_KEYS.signingCache),
    removeSession(STORAGE_KEYS.securityTicketState)
  ]);
  return getVaultState();
}

export async function requireUnlockedSession() {
  const [store, session] = await Promise.all([
    readWalletStore(),
    getSession(STORAGE_KEYS.session, null)
  ]);

  const restoredActiveAddress = resolveActiveAddress(store, session);
  if (
    session &&
    !sessionExpired(session) &&
    String(session.address || "").trim() === restoredActiveAddress
  ) {
    const refreshedSession = {
      ...session,
      address: restoredActiveAddress,
      unlockedAt: Date.now()
    };
    await setSession(STORAGE_KEYS.session, refreshedSession);
    return refreshedSession;
  }

  if (!session || sessionExpired(session)) {
    throw new Error("Cuzdan kilitli. Once extension icinden ac.");
  }

  const activeAddress = resolveActiveAddress(store, session);
  if (String(session.address || "").trim() !== activeAddress) {
    throw new Error("Secili cüzdan kilitli. Önce o cüzdanı PIN ile aç.");
  }

  await setSession(STORAGE_KEYS.session, {
    ...session,
    unlockedAt: Date.now()
  });

  return {
    ...session,
    address: activeAddress
  };
}

export async function extendUnlockedSessionExpiry(expiresAtMs) {
  const session = await requireUnlockedSession();
  const safeExpiryMs = Number(expiresAtMs);

  if (!Number.isFinite(safeExpiryMs) || safeExpiryMs <= Date.now()) {
    throw new Error("Gecersiz H-Cash otomatik teklif oturum suresi.");
  }

  const nextSession = {
    ...session,
    unlockedAt: Date.now(),
    expiresAt: safeExpiryMs
  };

  await setSession(STORAGE_KEYS.session, nextSession);
  return nextSession;
}

export async function approveOrigin(origin) {
  if (!isAllowedSiteOrigin(origin)) {
    throw new Error("Bu origin icin baglanti izni verilemez.");
  }

  const current = await getLocal(STORAGE_KEYS.approvedOrigins, []);
  const origins = Array.isArray(current) ? current : [];
  const next = Array.from(new Set([...origins, origin]));
  await setLocal(STORAGE_KEYS.approvedOrigins, next);
  return next;
}

export async function revokeOrigin(origin) {
  const current = await getLocal(STORAGE_KEYS.approvedOrigins, []);
  const origins = Array.isArray(current) ? current : [];
  const next = origins.filter((item) => item !== origin);
  await setLocal(STORAGE_KEYS.approvedOrigins, next);
  return next;
}

export async function requireApprovedUnlockedOrigin(origin) {
  if (!isAllowedSiteOrigin(origin)) {
    throw new Error("Origin izni yok.");
  }

  const approvedOrigins = await getLocal(STORAGE_KEYS.approvedOrigins, []);
  const origins = Array.isArray(approvedOrigins) ? approvedOrigins : [];
  if (!origins.includes(origin)) {
    throw new Error("Bu site için cüzdan izni verilmemis.");
  }

  return requireUnlockedSession();
}

export async function signTxHashForApprovedOrigin(origin, hashWithFee) {
  await requireApprovedUnlockedOrigin(origin);
  const session = await requireUnlockedSession();
  const signed = await signTxHash(session.privateKey, hashWithFee);
  return {
    address: session.address,
    ...signed
  };
}
