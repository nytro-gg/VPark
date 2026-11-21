// Regression tests: sessions are opaque server-issued tokens, never raw user IDs.
// This file covers the session manager itself and the LOCAL DEVELOPMENT store.
// The durable production store (Redis REST) is covered in security-session-redis.test.mjs.
import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setupApp } from './support/harness.mjs';
import { defineSessionEnforcementTests } from './support/session-suite.mjs';
import {
  createMemorySessionStore,
  createSessionManager,
  getSessionCookieName,
  hashSessionToken,
  resolveSessionSecret,
} from '../src/lib/security/session.mjs';
import { resolveSessionBackend } from '../src/lib/security/redis-session-store.mjs';

const app = await setupApp();
after(() => app.cleanup());

const SECRET = 'x'.repeat(48);
const DAY = 24 * 60 * 60 * 1000;

describe('Session manager (unit)', () => {
  it('issues opaque high-entropy tokens and stores only an HMAC of them', async () => {
    const store = createMemorySessionStore();
    const mgr = createSessionManager({ store, secret: SECRET });
    const { token, record } = await mgr.createSession({ userId: 'usr_driver_1' });
    assert.match(token, /^v1\.[A-Za-z0-9_-]{43}$/);
    assert.ok(!token.includes('usr_driver_1'));
    assert.equal(record.tokenHash, hashSessionToken(token, SECRET));
    assert.ok(![...store.records.values()].some((e) => JSON.stringify(e).includes(token.slice(3))));
    assert.equal((await mgr.validateSession(token)).userId, 'usr_driver_1');
  });

  it('rejects expired sessions (absolute lifetime) and idle sessions', async () => {
    let now = Date.parse('2026-11-01T00:00:00Z');
    const clock = () => now;
    const mgr = createSessionManager({ store: createMemorySessionStore({ now: clock }), secret: SECRET, now: clock });
    // Stay active (touch every day) so only the absolute lifetime can end it.
    const { token } = await mgr.createSession({ userId: 'u1' });
    for (let d = 0; d < 6; d++) {
      now += DAY;
      assert.ok(await mgr.validateSession(token), `still valid on day ${d + 1}`);
    }
    now += DAY + 1;
    assert.equal(await mgr.validateSession(token), null);

    now = Date.parse('2026-11-01T00:00:00Z');
    const idle = (await mgr.createSession({ userId: 'u1' })).token;
    now += mgr.config.idleTimeoutMs + 1;
    assert.equal(await mgr.validateSession(idle), null);
  });

  it('rotation revokes the previous token', async () => {
    const mgr = createSessionManager({ store: createMemorySessionStore(), secret: SECRET });
    const first = (await mgr.createSession({ userId: 'u1' })).token;
    const second = (await mgr.rotateSession(first, { userId: 'u1' })).token;
    assert.equal(await mgr.validateSession(first), null);
    assert.ok(await mgr.validateSession(second));
  });

  it('tokens minted under one secret are useless under another', async () => {
    const store = createMemorySessionStore();
    const token = (await createSessionManager({ store, secret: SECRET }).createSession({ userId: 'u1' })).token;
    assert.equal(await createSessionManager({ store, secret: 'y'.repeat(48) }).validateSession(token), null);
  });

  it('treats a failing session store as "no session" (fail closed) instead of throwing', async () => {
    const broken = {
      insert: async () => {
        throw new Error('down');
      },
      findByTokenHash: async () => {
        throw new Error('down');
      },
      touch: async () => false,
      remove: async () => {},
      removeAllForUser: async () => 0,
    };
    const mgr = createSessionManager({ store: broken, secret: SECRET, logger: { error() {} } });
    assert.equal(await mgr.validateSession(`v1.${'A'.repeat(43)}`), null);
    await assert.rejects(mgr.createSession({ userId: 'u1' }));
  });

  it('fails closed when SESSION_SECRET is missing or weak in production', () => {
    assert.equal(resolveSessionSecret({ NODE_ENV: 'production' }).secret, null);
    // Vercel is production too: a per-instance ephemeral secret would break sessions across instances.
    assert.equal(resolveSessionSecret({ NODE_ENV: 'production', VERCEL: '1' }).secret, null);
    assert.equal(resolveSessionSecret({ NODE_ENV: 'production', VPARK_ALLOW_LOCAL_FALLBACK: 'true' }).secret, null);
    assert.equal(resolveSessionSecret({ NODE_ENV: 'production', SESSION_SECRET: 'short' }).secret, null);
    assert.equal(resolveSessionSecret({ NODE_ENV: 'development', SESSION_SECRET: 'short' }).secret, null);
    assert.ok(resolveSessionSecret({ NODE_ENV: 'production', SESSION_SECRET: SECRET }).secret);
    assert.throws(() => createSessionManager({ store: createMemorySessionStore(), secret: '' }));
  });

  it('uses a __Host- prefixed cookie name in production', () => {
    assert.equal(getSessionCookieName({ NODE_ENV: 'production' }), '__Host-vpark_session');
  });

  it('stores sessions in the application database, which must be PostgreSQL in production', () => {
    // Development / test without DATABASE_URL: the local JSON development store.
    assert.equal(resolveSessionBackend({ NODE_ENV: 'development' }).kind, 'database');
    assert.equal(resolveSessionBackend({ NODE_ENV: 'test' }).kind, 'database');
    // Production never uses local files: PostgreSQL (or Redis) is required.
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production' }).kind, null);
    assert.equal(
      resolveSessionBackend({ NODE_ENV: 'production', DATABASE_URL: 'postgres://u:p@db.example.com/vpark?sslmode=require' }).kind,
      'database'
    );
  });
});

await defineSessionEnforcementTests('local development store', app, () => app.db.getSessionStore());

describe('Local development store persistence', () => {
  const dbFile = path.join(app.dataDir, 'vpark_database.json');
  const sessionsOnDisk = () => JSON.parse(fs.readFileSync(dbFile, 'utf-8')).sessions || [];

  it('writes sessions to disk as HMACs only', async () => {
    const token = await app.sessionFor('usr_driver_1');
    const onDisk = sessionsOnDisk();
    assert.ok(onDisk.some((s) => s.tokenHash === hashSessionToken(token, process.env.SESSION_SECRET)));
    assert.ok(!fs.readFileSync(dbFile, 'utf-8').includes(token));
  });

  it('pruning of expired and idle sessions is persisted to disk', async () => {
    // A live session first: creating sessions prunes too, and must not do the work for us below.
    const live = await app.sessionFor('usr_driver_1');
    const store = app.db.getSessionStore();
    const iso = (offsetMs) => new Date(Date.now() + offsetMs).toISOString();
    const fixture = (name, { createdAgo, expiresIn, lastSeenAgo }) => ({
      id: `ses_fixture_${name}`,
      tokenHash: `fixture-${name}-${Math.random().toString(36).slice(2)}`,
      userId: 'usr_driver_1',
      createdAt: iso(-createdAgo),
      expiresAt: iso(expiresIn),
      lastSeenAt: iso(-lastSeenAgo),
      revokedAt: null,
    });
    const expired = fixture('expired', { createdAgo: 8 * DAY, expiresIn: -DAY, lastSeenAgo: DAY });
    const idle = fixture('idle', { createdAgo: 4 * DAY, expiresIn: 3 * DAY, lastSeenAgo: 4 * DAY });
    await store.insert(expired, 1);
    await store.insert(idle, 1);
    const hashes = [expired.tokenHash, idle.tokenHash];
    assert.ok(hashes.every((h) => sessionsOnDisk().some((s) => s.tokenHash === h)), 'fixtures written');

    // Prune on its own (no other write follows); the result must reach the disk.
    await store.prune(new Date().toISOString(), new Date(Date.now() - 3 * DAY).toISOString());
    const afterPrune = sessionsOnDisk();
    assert.ok(hashes.every((h) => !afterPrune.some((s) => s.tokenHash === h)), 'expired / idle sessions removed from disk');
    assert.ok(afterPrune.some((s) => s.tokenHash === hashSessionToken(live, process.env.SESSION_SECRET)), 'live session kept');
  });
});
