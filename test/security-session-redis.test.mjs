// Regression tests for the DURABLE, SHARED production session store (Redis via the
// Upstash REST API). A local fake Upstash server stands in for the hosted Redis.
//
// Covers: backend selection and production fail-closed behaviour, store semantics,
// the full session-enforcement suite on the Redis backend, and persistence across
// independent instances and restarts (separate Node processes, separate disks).
import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { read, setupApp, TEST_PROJECT_ID } from './support/harness.mjs';
import { startFakeUpstash } from './support/fake-upstash.mjs';
import { defineSessionEnforcementTests } from './support/session-suite.mjs';
import {
  createRedisRestSessionStore,
  getRedisRestConfig,
  resolveSessionBackend,
} from '../src/lib/security/redis-session-store.mjs';
import { createSessionManager, hashSessionToken } from '../src/lib/security/session.mjs';

const exec = promisify(execFile);
const redis = await startFakeUpstash();
const app = await setupApp({ redis });
const tempDirs = [];
after(async () => {
  app.cleanup();
  for (const d of tempDirs) fs.rmSync(d, { recursive: true, force: true });
  await redis.close();
});

const SECRET = 'z'.repeat(48);
const storeFor = (overrides = {}) => createRedisRestSessionStore({ url: redis.url, token: redis.token, ...overrides });
const localSessionsOnDisk = (dir) => {
  const file = path.join(dir, 'vpark_database.json');
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf-8')).sessions || [] : [];
};

describe('Session backend selection', () => {
  const https = { UPSTASH_REDIS_REST_URL: 'https://example.upstash.io', UPSTASH_REDIS_REST_TOKEN: 't0k' };

  it('production without a durable store fails closed instead of using local files', () => {
    const r = resolveSessionBackend({ NODE_ENV: 'production' });
    assert.equal(r.kind, null);
    assert.match(r.error, /No durable session store/);
    // Not even on Vercel, where /tmp is per-instance and wiped on cold start.
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', VERCEL: '1' }).kind, null);
  });

  it('production with Redis REST credentials uses Redis (Upstash or Vercel KV variable names)', () => {
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', ...https }).kind, 'redis');
    const kv = resolveSessionBackend({ NODE_ENV: 'production', KV_REST_API_URL: https.UPSTASH_REDIS_REST_URL, KV_REST_API_TOKEN: 't' });
    assert.equal(kv.kind, 'redis');
  });

  it('rejects partial, insecure or malformed Redis configuration', () => {
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', UPSTASH_REDIS_REST_URL: https.UPSTASH_REDIS_REST_URL }).kind, null);
    assert.equal(resolveSessionBackend({ NODE_ENV: 'development', UPSTASH_REDIS_REST_TOKEN: 't' }).kind, null);
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', UPSTASH_REDIS_REST_URL: 'http://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 't' }).kind, null);
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', UPSTASH_REDIS_REST_URL: 'http://127.0.0.1:8080', UPSTASH_REDIS_REST_TOKEN: 't' }).kind, null);
    assert.equal(resolveSessionBackend({ NODE_ENV: 'production', ...https, VPARK_SESSION_KEY_PREFIX: 'bad prefix!' }).kind, null);
    assert.equal(resolveSessionBackend({ NODE_ENV: 'development', VPARK_SESSION_STORE: 'redis' }).kind, null);
  });

  it('never uses the read-only KV token', () => {
    const r = getRedisRestConfig({ KV_REST_API_URL: https.UPSTASH_REDIS_REST_URL, KV_REST_API_READ_ONLY_TOKEN: 'ro' });
    assert.ok(r.error, 'a read-only token alone must not configure the store');
  });

  it('a production app with no durable store refuses sessions and writes nothing locally', async () => {
    const { createGoogleSignInHandler } = await import('../src/lib/auth-google.ts');
    const saved = { ...process.env };
    process.env.NODE_ENV = 'production';
    process.env.VERCEL = '1';
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    const errors = [];
    const origError = console.error;
    console.error = (msg) => errors.push(String(msg));
    try {
      const before = localSessionsOnDisk(app.dataDir).length;
      let verifierCalled = false;
      const handler = createGoogleSignInHandler({ verifier: async () => ((verifierCalled = true), {}) });
      const res = await handler(app.request('POST', '/api/auth/google', { body: { idToken: 'a.b.c' } }));
      assert.equal(res.status, 503);
      assert.equal(verifierCalled, false, 'no identity work happens without a session store');
      assert.equal(res.cookies.get('__Host-vpark_session'), undefined);
      assert.equal(localSessionsOnDisk(app.dataDir).length, before);
      assert.ok(errors.some((e) => e.includes('No durable session store')), 'a clear configuration error is logged');

      // Existing session cookies are not honoured either.
      const me = await import('../src/app/api/auth/me/route.ts');
      const who = await read(
        await me.GET(app.request('GET', '/api/auth/me', { cookie: `__Host-vpark_session=v1.${'A'.repeat(43)}` }))
      );
      assert.equal(who.json.user, null);
    } finally {
      console.error = origError;
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });
});

describe('Redis REST session store (unit)', () => {
  it('stores only token HMACs, with a TTL bounded by the idle timeout', async () => {
    const mgr = createSessionManager({ store: storeFor(), secret: SECRET });
    const { token, record } = await mgr.createSession({ userId: 'u-redis-1' });
    const keys = redis.keys();
    assert.ok(keys.includes(`vpark:session:t:${hashSessionToken(token, SECRET)}`));
    assert.ok(!keys.some((k) => k.includes(token)));
    const ttl = redis.ttl(`vpark:session:t:${record.tokenHash}`);
    assert.ok(ttl > 0 && ttl <= mgr.config.idleTimeoutMs, `ttl ${ttl}`);
  });

  it('expired keys are removed by Redis itself (durable pruning)', async () => {
    const store = storeFor();
    const mgr = createSessionManager({ store, secret: SECRET, options: { idleTimeoutMs: 60, touchIntervalMs: 10 } });
    const { token, record } = await mgr.createSession({ userId: 'u-redis-ttl' });
    assert.ok(await mgr.validateSession(token));
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(await store.findByTokenHash(record.tokenHash), undefined);
    assert.equal(await mgr.validateSession(token), null);
  });

  it('a touch from another instance never resurrects a revoked session', async () => {
    const a = createSessionManager({ store: storeFor(), secret: SECRET });
    const { token, record } = await a.createSession({ userId: 'u-redis-2' });

    // Force the race: instance B's touch reads the record, then instance A revokes
    // it, then B writes. B's write must not bring the session back.
    let revokedMidTouch = false;
    const racingFetch = async (url, init) => {
      const body = JSON.parse(init.body);
      if (!revokedMidTouch && Array.isArray(body) && body[0] === 'SET' && body[1].endsWith(record.tokenHash)) {
        revokedMidTouch = true;
        await a.revokeSession(token);
      }
      return fetch(url, init);
    };
    const resurrected = await storeFor({ fetchImpl: racingFetch }).touch(record.tokenHash, new Date().toISOString(), 60_000);
    assert.ok(revokedMidTouch, 'the race was exercised');
    assert.equal(resurrected, false);
    assert.equal(await storeFor().findByTokenHash(record.tokenHash), undefined);
    assert.equal(await a.validateSession(token), null);
  });

  it('revokes every session of a user across instances', async () => {
    const a = createSessionManager({ store: storeFor(), secret: SECRET });
    const b = createSessionManager({ store: storeFor(), secret: SECRET });
    const t1 = (await a.createSession({ userId: 'u-redis-3' })).token;
    const t2 = (await b.createSession({ userId: 'u-redis-3' })).token;
    const other = (await b.createSession({ userId: 'u-redis-4' })).token;
    assert.equal(await b.revokeAllForUser('u-redis-3'), 2);
    assert.equal(await a.validateSession(t1), null);
    assert.equal(await a.validateSession(t2), null);
    assert.ok(await a.validateSession(other));
  });

  it('fails closed when Redis rejects the credentials or is unreachable', async () => {
    const silent = { error() {} };
    const good = createSessionManager({ store: storeFor(), secret: SECRET });
    const { token } = await good.createSession({ userId: 'u-redis-5' });

    const wrongToken = createSessionManager({ store: storeFor({ token: 'wrong' }), secret: SECRET, logger: silent });
    assert.equal(await wrongToken.validateSession(token), null);
    await assert.rejects(wrongToken.createSession({ userId: 'u-redis-5' }));

    const unreachable = createSessionManager({
      store: storeFor({ url: 'http://127.0.0.1:1', timeoutMs: 500 }),
      secret: SECRET,
      logger: silent,
    });
    assert.equal(await unreachable.validateSession(token), null);
    await assert.rejects(unreachable.createSession({ userId: 'u-redis-5' }), (err) => !String(err.message).includes(redis.token));
  });
});

await defineSessionEnforcementTests('durable Redis store', app, () =>
  createRedisRestSessionStore({ url: redis.url, token: redis.token })
);

describe('The app uses Redis (not local files) when it is configured', () => {
  it('sessions issued by the app live in Redis and never in the local data file', async () => {
    const token = await app.sessionFor('usr_driver_1');
    assert.ok(redis.keys().includes(`vpark:session:t:${hashSessionToken(token, process.env.SESSION_SECRET)}`));
    assert.equal(localSessionsOnDisk(app.dataDir).length, 0);
  });
});

describe('Persistence across independent instances and restarts', () => {
  const worker = fileURLToPath(new URL('./support/session-instance-worker.mjs', import.meta.url));
  const sharedSecret = crypto.randomBytes(48).toString('base64url');
  const newDisk = () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'vpark-instance-'));
    tempDirs.push(d);
    return d;
  };
  async function instance(dataDir, command, arg) {
    const { stdout } = await exec(process.execPath, [worker, command, arg], {
      env: {
        ...process.env,
        WORKER_REDIS_URL: redis.url,
        WORKER_REDIS_TOKEN: redis.token,
        WORKER_SESSION_SECRET: sharedSecret,
        WORKER_DATA_DIR: dataDir,
      },
      timeout: 60_000,
    });
    return JSON.parse(stdout.trim().split('\n').pop());
  }

  it('a session created on one instance is valid on others, survives restarts, and logout is global', async () => {
    const diskA = newDisk();
    const diskB = newDisk();
    const diskC = newDisk();

    const { token } = await instance(diskA, 'create', 'usr_driver_1');
    assert.match(token, /^v1\./);

    // Another instance with its own (empty) disk sees the session.
    assert.deepEqual(await instance(diskB, 'whoami', token), { status: 200, userId: 'usr_driver_1' });
    // Instance A restarts (new process, same disk): still signed in.
    assert.deepEqual(await instance(diskA, 'whoami', token), { status: 200, userId: 'usr_driver_1' });
    // A brand-new instance after a "deployment": still signed in.
    assert.deepEqual(await instance(diskC, 'whoami', token), { status: 200, userId: 'usr_driver_1' });

    // Logout on B revokes it everywhere, including on A after another restart.
    assert.equal((await instance(diskB, 'logout', token)).status, 200);
    assert.deepEqual(await instance(diskA, 'whoami', token), { status: 200, userId: null });
    assert.deepEqual(await instance(diskC, 'whoami', token), { status: 200, userId: null });

    // No instance ever wrote a session to its local disk.
    for (const d of [diskA, diskB, diskC]) assert.equal(localSessionsOnDisk(d).length, 0, `local sessions found in ${d}`);
    assert.ok(TEST_PROJECT_ID);
  });
});
