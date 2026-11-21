// Server-side session management for VPark.
//
// Design: opaque, high-entropy random session tokens backed by a server-side
// session store. The browser only ever holds the random token (in an HttpOnly
// cookie); the store only ever holds an HMAC-SHA256 of that token keyed with
// SESSION_SECRET. A database user ID (or anything else that is not a token this
// server issued) can never authenticate.
//
// The store is pluggable and asynchronous so production can use a durable,
// shared backend (see redis-session-store.mjs) while tests and local development
// use in-process or file-backed stores. This module is framework-free and
// dependency-injected (store, secret, clock) so it can be unit-tested directly.

import crypto from 'node:crypto';

export const SESSION_TOKEN_VERSION = 'v1';
const TOKEN_RANDOM_BYTES = 32; // 256 bits of entropy
// "v1." + base64url(32 bytes) => 43 base64url characters, no padding.
const TOKEN_PATTERN = /^v1\.[A-Za-z0-9_-]{43}$/;

export const MIN_SESSION_SECRET_LENGTH = 32;

/** Cookie used before this hardening release. It carried a raw user ID and is never trusted. */
export const LEGACY_SESSION_COOKIE_NAME = 'vpark_user_id';

export const SESSION_DEFAULTS = Object.freeze({
  /** Hard upper bound on a session's lifetime, regardless of activity. */
  absoluteTtlMs: 7 * 24 * 60 * 60 * 1000,
  /** A session unused for this long is revoked. */
  idleTimeoutMs: 3 * 24 * 60 * 60 * 1000,
  /** How often lastSeenAt (and the store TTL) is refreshed; limits store writes. */
  touchIntervalMs: 15 * 60 * 1000,
});

/**
 * In production the `__Host-` prefix forces Secure, Path=/ and no Domain attribute,
 * so the cookie cannot be set or shadowed by a sibling subdomain.
 */
export function getSessionCookieName(env = process.env) {
  return env.NODE_ENV === 'production' ? '__Host-vpark_session' : 'vpark_session';
}

let warnedEphemeralSecret = false;

/**
 * Resolve the HMAC key used to hash session tokens.
 * - SESSION_SECRET set and >= 32 chars: used as-is.
 * - SESSION_SECRET set but too short: configuration error in every environment (fail closed).
 * - SESSION_SECRET missing in production: configuration error (fail closed).
 * - SESSION_SECRET missing outside production: a random per-process secret is generated, so
 *   local development works but every restart signs everyone out.
 */
export function resolveSessionSecret(env = process.env) {
  const raw = typeof env.SESSION_SECRET === 'string' ? env.SESSION_SECRET.trim() : '';
  if (raw) {
    if (raw.length < MIN_SESSION_SECRET_LENGTH) {
      return { secret: null, error: `SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters.` };
    }
    return { secret: raw, source: 'env' };
  }
  // Never an ephemeral per-instance secret in production (incl. Vercel): sessions would not validate across instances.
  if (env.NODE_ENV === 'production') {
    return { secret: null, error: 'SESSION_SECRET is not configured.' };
  }
  const g = globalThis;
  if (!g.__vparkEphemeralSessionSecret) {
    g.__vparkEphemeralSessionSecret = crypto.randomBytes(32).toString('base64url');
  }
  if (!warnedEphemeralSecret && env.NODE_ENV !== 'test') {
    warnedEphemeralSecret = true;
    console.warn(
      '[auth] SESSION_SECRET is not set; using an ephemeral development secret. Sessions will not survive a restart.'
    );
  }
  return { secret: g.__vparkEphemeralSessionSecret, source: 'ephemeral' };
}

export function generateSessionToken() {
  return `${SESSION_TOKEN_VERSION}.${crypto.randomBytes(TOKEN_RANDOM_BYTES).toString('base64url')}`;
}

export function isWellFormedSessionToken(token) {
  return typeof token === 'string' && TOKEN_PATTERN.test(token);
}

export function hashSessionToken(token, secret) {
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

function sanitizeUserAgent(ua) {
  if (typeof ua !== 'string') return undefined;
  return ua.slice(0, 200);
}

/**
 * Create a session manager bound to a store.
 *
 * Store contract (every method may return a Promise):
 *   insert(record, ttlMs)                    create a session record that expires after ttlMs
 *   findByTokenHash(tokenHash)               -> record | undefined
 *   touch(tokenHash, lastSeenAtIso, ttlMs)   refresh lastSeenAt + TTL, but ONLY if the record
 *                                            still exists (must never resurrect a revoked session)
 *   remove(tokenHash)                        delete one session (revocation)
 *   removeAllForUser(userId)                 -> number of sessions deleted
 *   prune?(nowIso, idleCutoffIso)            optional: durably delete expired / idle records
 *
 * Revocation deletes the record, so a revoked session cannot be revived by a
 * concurrent touch on another instance.
 */
export function createSessionManager({ store, secret, now = () => Date.now(), options = {}, logger = console } = {}) {
  if (!store) throw new Error('Session store is required.');
  if (typeof secret !== 'string' || secret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error('A session secret of sufficient length is required.');
  }
  const cfg = { ...SESSION_DEFAULTS, ...options };

  /** Store TTL: the earlier of the idle deadline and the absolute expiry. */
  function storeTtlMs(record, nowMs) {
    return Math.max(1, Math.min(cfg.idleTimeoutMs, Date.parse(record.expiresAt) - nowMs));
  }

  async function createSession({ userId, userAgent } = {}) {
    if (typeof userId !== 'string' || !userId) throw new Error('userId is required to create a session.');
    const nowMs = now();
    const token = generateSessionToken();
    const record = {
      id: `ses_${crypto.randomBytes(12).toString('hex')}`,
      tokenHash: hashSessionToken(token, secret),
      userId,
      createdAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + cfg.absoluteTtlMs).toISOString(),
      lastSeenAt: new Date(nowMs).toISOString(),
      revokedAt: null,
      userAgent: sanitizeUserAgent(userAgent),
    };
    if (typeof store.prune === 'function') {
      await store.prune(record.createdAt, new Date(nowMs - cfg.idleTimeoutMs).toISOString());
    }
    await store.insert(record, storeTtlMs(record, nowMs));
    return { token, record };
  }

  /**
   * Returns the live session record for a token, or null. Never throws: a store
   * failure is logged and treated as "no session" (fail closed).
   */
  async function validateSession(token) {
    if (!isWellFormedSessionToken(token)) return null;
    const tokenHash = hashSessionToken(token, secret);
    try {
      const record = await store.findByTokenHash(tokenHash);
      if (!record || record.revokedAt) return null;

      const nowMs = now();
      const expiresAtMs = Date.parse(record.expiresAt);
      const lastSeenMs = Date.parse(record.lastSeenAt);
      if (
        !Number.isFinite(expiresAtMs) ||
        nowMs >= expiresAtMs ||
        !Number.isFinite(lastSeenMs) ||
        nowMs - lastSeenMs >= cfg.idleTimeoutMs
      ) {
        await store.remove(tokenHash);
        return null;
      }
      if (nowMs - lastSeenMs >= cfg.touchIntervalMs) {
        const lastSeenAt = new Date(nowMs).toISOString();
        await store.touch(tokenHash, lastSeenAt, storeTtlMs(record, nowMs));
        return { ...record, lastSeenAt };
      }
      return record;
    } catch (err) {
      logger.error(`[auth] Session store unavailable during validation: ${err && err.message ? err.message : err}`);
      return null;
    }
  }

  async function revokeSession(token) {
    if (!isWellFormedSessionToken(token)) return false;
    await store.remove(hashSessionToken(token, secret));
    return true;
  }

  async function revokeAllForUser(userId) {
    if (typeof userId !== 'string' || !userId) return 0;
    return store.removeAllForUser(userId);
  }

  /** Issue a fresh token for a user and revoke the previously presented one (if any). */
  async function rotateSession(previousToken, params) {
    if (previousToken) await revokeSession(previousToken);
    return createSession(params);
  }

  return {
    createSession,
    validateSession,
    revokeSession,
    revokeAllForUser,
    rotateSession,
    config: Object.freeze({ ...cfg }),
  };
}

/**
 * In-process store implementing the session store contract. For unit tests only:
 * it is neither durable nor shared between instances.
 */
export function createMemorySessionStore({ now = () => Date.now() } = {}) {
  const records = new Map(); // tokenHash -> { record, expiresAtMs }
  const live = (hash) => {
    const entry = records.get(hash);
    if (!entry) return undefined;
    if (entry.expiresAtMs <= now()) {
      records.delete(hash);
      return undefined;
    }
    return entry;
  };
  return {
    records,
    async insert(record, ttlMs) {
      records.set(record.tokenHash, { record: { ...record }, expiresAtMs: now() + ttlMs });
    },
    async findByTokenHash(tokenHash) {
      const entry = live(tokenHash);
      return entry ? { ...entry.record } : undefined;
    },
    async touch(tokenHash, lastSeenAt, ttlMs) {
      const entry = live(tokenHash);
      if (!entry) return false;
      entry.record.lastSeenAt = lastSeenAt;
      entry.expiresAtMs = now() + ttlMs;
      return true;
    },
    async remove(tokenHash) {
      records.delete(tokenHash);
    },
    async removeAllForUser(userId) {
      let count = 0;
      for (const [hash, entry] of records) {
        if (entry.record.userId === userId) {
          records.delete(hash);
          count += 1;
        }
      }
      return count;
    },
  };
}
