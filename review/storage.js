export async function getLocal(key, fallbackValue) {
  const result = await chrome.storage.local.get(key);
  return result[key] ?? fallbackValue;
}

export async function setLocal(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

export async function removeLocal(key) {
  await chrome.storage.local.remove(key);
}

export async function getSession(key, fallbackValue) {
  const store = chrome.storage.session;
  if (!store) {
    throw new Error("Bu Chrome surumunde guvenli session storage desteklenmiyor.");
  }
  const result = await store.get(key);
  return result[key] ?? fallbackValue;
}

export async function setSession(key, value) {
  const store = chrome.storage.session;
  if (!store) {
    throw new Error("Bu Chrome surumunde guvenli session storage desteklenmiyor.");
  }
  await store.set({ [key]: value });
}

export async function removeSession(key) {
  const store = chrome.storage.session;
  if (!store) {
    throw new Error("Bu Chrome surumunde guvenli session storage desteklenmiyor.");
  }
  await store.remove(key);
}
