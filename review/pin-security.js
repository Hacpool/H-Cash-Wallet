import {
  PIN_LOCKOUT_MAX_MS,
  PIN_LOCKOUT_THRESHOLD,
  STORAGE_KEYS
} from "./config.js";
import { getLocal, setLocal } from "./storage.js";

function createDefaultSecurityState() {
  return {
    failedPinAttempts: 0,
    lockoutUntil: 0,
    lastFailureAt: 0
  };
}

function normalizeSecurityState(rawState) {
  return {
    failedPinAttempts: Number(rawState?.failedPinAttempts || 0),
    lockoutUntil: Number(rawState?.lockoutUntil || 0),
    lastFailureAt: Number(rawState?.lastFailureAt || 0)
  };
}

function formatDuration(ms) {
  const totalSeconds = Math.max(1, Math.ceil(ms / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return `${hours}s ${Math.max(1, minutes)}dk`;
  }

  if (minutes > 0) {
    return `${minutes}dk ${Math.max(1, seconds)}sn`;
  }

  return `${seconds}sn`;
}

function computeLockoutMs(failedPinAttempts) {
  if (failedPinAttempts < PIN_LOCKOUT_THRESHOLD) {
    return 0;
  }

  const schedule = [
    30 * 1000,
    5 * 60 * 1000,
    15 * 60 * 1000,
    60 * 60 * 1000,
    6 * 60 * 60 * 1000,
    PIN_LOCKOUT_MAX_MS
  ];

  const index = Math.min(
    failedPinAttempts - PIN_LOCKOUT_THRESHOLD,
    schedule.length - 1
  );
  return schedule[index];
}

export async function readPinSecurityState() {
  const rawState = await getLocal(STORAGE_KEYS.securityState, null);
  return normalizeSecurityState(rawState ?? createDefaultSecurityState());
}

export async function assertPinEntryAllowed() {
  const state = await readPinSecurityState();
  const now = Date.now();
  if (state.lockoutUntil > now) {
    throw new Error(
      `Cuzdan gecici olarak kilitlendi. ${formatDuration(state.lockoutUntil - now)} sonra tekrar deneyin.`
    );
  }
}

export async function notePinSuccess() {
  await setLocal(STORAGE_KEYS.securityState, createDefaultSecurityState());
}

export async function notePinFailure() {
  const previousState = await readPinSecurityState();
  const now = Date.now();
  const failedPinAttempts = previousState.failedPinAttempts + 1;
  const lockoutMs = computeLockoutMs(failedPinAttempts);
  const lockoutUntil = lockoutMs > 0 ? now + lockoutMs : 0;

  await setLocal(STORAGE_KEYS.securityState, {
    failedPinAttempts,
    lockoutUntil,
    lastFailureAt: now
  });

  if (lockoutMs > 0) {
    return `Hatali PIN. Cuzdan ${formatDuration(lockoutMs)} boyunca gecici olarak kilitlendi.`;
  }

  return "Hatali PIN.";
}
