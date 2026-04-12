type CacheScope = "session" | "persistent" | "both";

type CacheEnvelope<T> = {
  value: T;
  savedAt: number;
  expiresAt: number;
};

type CacheWriteOptions = {
  ttlMs: number;
  scope?: CacheScope;
  maxPersistentSizeBytes?: number;
};

const CACHE_PREFIX = "sentinelflow:cache:";
const memoryCache = new Map<string, CacheEnvelope<unknown>>();

function isBrowser() {
  return typeof window !== "undefined";
}

function getSessionStorage() {
  if (!isBrowser()) {
    return null;
  }

  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function getLocalStorage() {
  if (!isBrowser()) {
    return null;
  }

  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function buildStorageKey(key: string, scope: Exclude<CacheScope, "both">) {
  return `${CACHE_PREFIX}${scope}:${key}`;
}

function isExpired(envelope: CacheEnvelope<unknown>, now = Date.now()) {
  return envelope.expiresAt <= now;
}

function readEnvelopeFromStorage<T>(storage: Storage | null, key: string): CacheEnvelope<T> | null {
  if (!storage) {
    return null;
  }

  try {
    const raw = storage.getItem(key);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as CacheEnvelope<T>;
    if (!parsed || typeof parsed !== "object") {
      return null;
    }

    if (typeof parsed.expiresAt !== "number" || typeof parsed.savedAt !== "number") {
      return null;
    }

    if (isExpired(parsed)) {
      storage.removeItem(key);
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function writeEnvelopeToStorage<T>(storage: Storage | null, key: string, envelope: CacheEnvelope<T>) {
  if (!storage) {
    return;
  }

  try {
    storage.setItem(key, JSON.stringify(envelope));
  } catch {
    // Ignore storage quota and serialization failures.
  }
}

function removeEnvelopeFromStorage(storage: Storage | null, key: string) {
  if (!storage) {
    return;
  }

  try {
    storage.removeItem(key);
  } catch {
    // Ignore storage access failures.
  }
}

export function hashString(input: string): string {
  let hash = 2166136261;

  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  return (hash >>> 0).toString(36);
}

export function createCacheKey(...parts: Array<string | number | boolean | null | undefined>): string {
  return parts
    .map((part) => {
      if (part === null) {
        return "null";
      }

      if (part === undefined) {
        return "undefined";
      }

      return String(part);
    })
    .join("::");
}

export function getCachedValue<T>(key: string): T | null {
  const now = Date.now();
  const memoryEntry = memoryCache.get(key);

  if (memoryEntry) {
    if (!isExpired(memoryEntry, now)) {
      return memoryEntry.value as T;
    }

    memoryCache.delete(key);
  }

  const sessionKey = buildStorageKey(key, "session");
  const persistentKey = buildStorageKey(key, "persistent");
  const sessionEntry = readEnvelopeFromStorage<T>(getSessionStorage(), sessionKey);

  if (sessionEntry) {
    memoryCache.set(key, sessionEntry);
    return sessionEntry.value;
  }

  const persistentEntry = readEnvelopeFromStorage<T>(getLocalStorage(), persistentKey);
  if (persistentEntry) {
    memoryCache.set(key, persistentEntry);
    return persistentEntry.value;
  }

  return null;
}

export function setCachedValue<T>(key: string, value: T, options: CacheWriteOptions) {
  const now = Date.now();
  const envelope: CacheEnvelope<T> = {
    value,
    savedAt: now,
    expiresAt: now + options.ttlMs,
  };
  const scope = options.scope ?? "both";

  memoryCache.set(key, envelope);

  if (scope === "session" || scope === "both") {
    writeEnvelopeToStorage(getSessionStorage(), buildStorageKey(key, "session"), envelope);
  }

  if (scope === "persistent" || scope === "both") {
    const serialized = JSON.stringify(envelope);
    if (!options.maxPersistentSizeBytes || serialized.length <= options.maxPersistentSizeBytes) {
      writeEnvelopeToStorage(getLocalStorage(), buildStorageKey(key, "persistent"), envelope);
    }
  }
}

export function clearCachedValue(key: string) {
  memoryCache.delete(key);
  removeEnvelopeFromStorage(getSessionStorage(), buildStorageKey(key, "session"));
  removeEnvelopeFromStorage(getLocalStorage(), buildStorageKey(key, "persistent"));
}

export function clearCacheNamespace(namespace: string) {
  for (const key of Array.from(memoryCache.keys())) {
    if (key.startsWith(namespace)) {
      memoryCache.delete(key);
    }
  }

  if (!isBrowser()) {
    return;
  }

  const storages = [getSessionStorage(), getLocalStorage()];

  for (const storage of storages) {
    if (!storage) {
      continue;
    }

    const keysToDelete: string[] = [];

    for (let index = 0; index < storage.length; index += 1) {
      const storageKey = storage.key(index);
      if (storageKey && storageKey.startsWith(CACHE_PREFIX) && storageKey.includes(namespace)) {
        keysToDelete.push(storageKey);
      }
    }

    keysToDelete.forEach((storageKey) => storage.removeItem(storageKey));
  }
}
