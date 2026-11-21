// Durable, shared session store backed by Redis via the Upstash REST API
// (also what Vercel's Marketplace Redis / KV integration provides).
//
// Why this backend: every serverless instance talks to the same Redis over HTTPS,
// sessions survive deployments, cold starts and restarts, and Redis key TTLs
// expire sessions natively (expired and idle sessions are deleted durably by the
// server, no sweep needed). It uses plain `fetch`, so no client library is added.
//
// Data model (all keys share a configurable prefix, default "vpark:session:"):
//   <prefix>t:<tokenHash>  -> JSON session record, TTL = min(idle timeout, time to absolute expiry)
//   <prefix>u:<userId>     -> SET of tokenHashes, used to revoke every session of a user
//
// Raw session tokens are never sent to Redis; only HMAC-SHA256 hashes of them.

import { resolveDataBackend } from '../data/config.mjs';

const DEFAULT_KEY_PREFIX = 'vpark:session:';
const KEY_PREFIX_PATTERN = /^[A-Za-z0-9:_-]{1,64}$/;
/** The per-user index outlives any single session (absolute lifetime is 7 days). */
const DEFAULT_USER_INDEX_TTL_MS = 8 * 24 * 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 5000;

function isLoopbackHost(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

/**
 * Read Redis REST settings. Supports Upstash's variable names and the
 * KV_REST_API_* names created by Vercel's integration. The read-only token is
 * deliberately never used.
 */
export function getRedisRestConfig(env = process.env) {
  const url = (env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL || '').trim();
  const token = (env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN || '').trim();
  if (!url && !token) return { config: null };
  if (!url || !token) {
    return { error: 'Redis REST session store is partially configured: both the REST URL and the REST token are required.' };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { error: 'The Redis REST URL is not a valid URL.' };
  }
  const insecureAllowed = env.NODE_ENV !== 'production' && isLoopbackHost(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && insecureAllowed)) {
    return { error: 'The Redis REST URL must use https:// (plain http is only allowed for localhost outside production).' };
  }
  const keyPrefix = (env.VPARK_SESSION_KEY_PREFIX || DEFAULT_KEY_PREFIX).trim();
  if (!KEY_PREFIX_PATTERN.test(keyPrefix)) {
    return { error: 'VPARK_SESSION_KEY_PREFIX may only contain letters, digits, ":", "_" and "-" (max 64).' };
  }
  return { config: { url: url.replace(/\/+$/, ''), token, keyPrefix } };
}

/**
 * Decide where sessions live.
 *   - Redis REST configured              -> durable shared Redis store ("redis")
 *   - VPARK_SESSION_STORE=redis, no Redis -> configuration error
 *   - PostgreSQL configured (DATABASE_URL)-> the application database ("database"), durable and shared
 *   - otherwise, in production            -> configuration error (fail closed; never local files)
 *   - otherwise (development / test)      -> the local JSON development store ("database")
 */
export function resolveSessionBackend(env = process.env) {
  const redis = getRedisRestConfig(env);
  if (redis.error) return { kind: null, error: redis.error };
  if (redis.config) return { kind: 'redis', config: redis.config };
  if ((env.VPARK_SESSION_STORE || '').trim().toLowerCase() === 'redis') {
    return { kind: null, error: 'VPARK_SESSION_STORE=redis is set but no Redis REST URL/token is configured.' };
  }
  const data = resolveDataBackend(env);
  if (data.kind === 'postgres') return { kind: 'database' };
  if (env.NODE_ENV === 'production') {
    return {
      kind: null,
      error:
        'No durable session store is configured. Set DATABASE_URL (PostgreSQL) or UPSTASH_REDIS_REST_URL and ' +
        'UPSTASH_REDIS_REST_TOKEN. Local files are never used for sessions in production.',
    };
  }
  if (data.kind === null) return { kind: null, error: data.error };
  return { kind: 'database' };
}

function parseRecord(raw) {
  if (typeof raw !== 'string') return undefined;
  try {
    const r = JSON.parse(raw);
    if (
      r &&
      typeof r.id === 'string' &&
      typeof r.tokenHash === 'string' &&
      typeof r.userId === 'string' &&
      typeof r.expiresAt === 'string' &&
      typeof r.lastSeenAt === 'string'
    ) {
      return r;
    }
  } catch {
    // corrupt value: treated as no session
  }
  return undefined;
}

export function createRedisRestSessionStore({
  url,
  token,
  keyPrefix = DEFAULT_KEY_PREFIX,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  userIndexTtlMs = DEFAULT_USER_INDEX_TTL_MS,
} = {}) {
  if (!url || !token) throw new Error('Redis REST URL and token are required.');
  if (typeof fetchImpl !== 'function') throw new Error('fetch is not available.');
  const base = url.replace(/\/+$/, '');
  const sessionKey = (hash) => `${keyPrefix}t:${hash}`;
  const userKey = (userId) => `${keyPrefix}u:${userId}`;

  async function post(path, body) {
    let res;
    try {
      res = await fetchImpl(`${base}${path}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      // Never include the URL or token in errors.
      throw new Error(`Redis REST request failed (${err && err.name ? err.name : 'network error'}).`);
    }
    let json;
    try {
      json = await res.json();
    } catch {
      throw new Error(`Redis REST returned a non-JSON response (HTTP ${res.status}).`);
    }
    if (!res.ok && !Array.isArray(json)) {
      throw new Error(`Redis REST error (HTTP ${res.status}): ${json && json.error ? String(json.error) : 'unknown'}`);
    }
    return json;
  }

  async function command(...args) {
    const json = await post('', args.map(String));
    if (json && json.error) throw new Error(`Redis REST command failed: ${json.error}`);
    return json ? json.result : undefined;
  }

  /** MULTI/EXEC: all commands apply atomically. */
  async function transaction(commands) {
    const json = await post('/multi-exec', commands.map((c) => c.map(String)));
    if (!Array.isArray(json)) throw new Error('Redis REST transaction returned an unexpected response.');
    for (const entry of json) {
      if (entry && entry.error) throw new Error(`Redis REST transaction failed: ${entry.error}`);
    }
    return json.map((entry) => entry.result);
  }

  return {
    kind: 'redis',

    async insert(record, ttlMs) {
      await transaction([
        ['SET', sessionKey(record.tokenHash), JSON.stringify(record), 'PX', Math.max(1, Math.ceil(ttlMs))],
        ['SADD', userKey(record.userId), record.tokenHash],
        ['PEXPIRE', userKey(record.userId), userIndexTtlMs],
      ]);
    },

    async findByTokenHash(tokenHash) {
      return parseRecord(await command('GET', sessionKey(tokenHash)));
    },

    async touch(tokenHash, lastSeenAt, ttlMs) {
      const record = parseRecord(await command('GET', sessionKey(tokenHash)));
      if (!record) return false;
      // XX: only overwrite if the key still exists, so a session revoked by another
      // instance between the GET and this SET is never brought back.
      const result = await command(
        'SET',
        sessionKey(tokenHash),
        JSON.stringify({ ...record, lastSeenAt }),
        'PX',
        Math.max(1, Math.ceil(ttlMs)),
        'XX'
      );
      return result === 'OK';
    },

    async remove(tokenHash) {
      const record = parseRecord(await command('GET', sessionKey(tokenHash)));
      if (record) {
        await transaction([
          ['DEL', sessionKey(tokenHash)],
          ['SREM', userKey(record.userId), tokenHash],
        ]);
      } else {
        await command('DEL', sessionKey(tokenHash));
      }
    },

    async removeAllForUser(userId) {
      const members = await command('SMEMBERS', userKey(userId));
      if (!Array.isArray(members) || members.length === 0) return 0;
      const [deleted] = await transaction([
        ['DEL', ...members.map(sessionKey)],
        // Remove only the members we saw; a session created concurrently stays indexed.
        ['SREM', userKey(userId), ...members],
      ]);
      return Number(deleted) || 0;
    },
    // No prune(): Redis deletes expired and idle sessions itself via key TTLs.
  };
}
