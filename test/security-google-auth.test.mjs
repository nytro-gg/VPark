// Regression tests: Google sign-in trusts only a server-verified Firebase ID token.
//
// The cryptographic verifier is injected (mocked) so no live Firebase project or
// credentials are needed. Separate cases exercise the real Firebase Admin SDK
// verifier against tokens it can reject offline.
import { after, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_UID, ORIGIN, TEST_PROJECT_ID, read, sessionTokenFrom, setupApp } from './support/harness.mjs';
import {
  createFirebaseAdminVerifier,
  evaluateFirebaseClaims,
  verifyFirebaseIdToken,
} from '../src/lib/security/firebase-identity.mjs';

const app = await setupApp();
const { db, request } = app;
const { createGoogleSignInHandler } = await import('../src/lib/auth-google.ts');
const me = await import('../src/app/api/auth/me/route.ts');
const adminListings = await import('../src/app/api/admin/listings/route.ts');
const onboarding = await import('../src/app/api/auth/onboarding/route.ts');
const logout = await import('../src/app/api/auth/logout/route.ts');

after(() => app.cleanup());

// --- Mock verifier: knows a set of "validly signed" tokens and their claims. ---
const signed = new Map();
let verifierCalls = 0;
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

function claimsFor(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const uid = overrides.sub ?? 'google-uid-alice';
  return {
    iss: `https://securetoken.google.com/${TEST_PROJECT_ID}`,
    aud: TEST_PROJECT_ID,
    sub: uid,
    uid,
    iat: now - 5,
    exp: now + 3600,
    auth_time: now - 5,
    email: 'alice@example.com',
    email_verified: true,
    name: 'Alice Example',
    firebase: { sign_in_provider: 'google.com' },
    ...overrides,
  };
}

function mintToken(claims) {
  const token = `${b64({ alg: 'RS256', kid: 'test-key' })}.${b64(claims)}.${Buffer.from(`sig-${signed.size}`).toString('base64url')}`;
  signed.set(token, claims);
  return token;
}

async function mockVerifier(token, projectId) {
  verifierCalls += 1;
  const claims = signed.get(token);
  if (!claims) throw Object.assign(new Error('invalid signature'), { code: 'auth/argument-error' });
  // Mimic the Admin SDK's own project binding check.
  if (claims.aud !== projectId) throw Object.assign(new Error('bad aud'), { code: 'auth/argument-error' });
  return claims;
}

const handler = createGoogleSignInHandler({ verifier: mockVerifier });

async function signIn(body, opts = {}) {
  const res = await handler(request('POST', '/api/auth/google', { body, ...opts }));
  return { ...(await read(res)), token: sessionTokenFrom(res) };
}

const userCount = async () => (await db.getUsers()).length;

beforeEach(() => {
  verifierCalls = 0;
});

describe('Rejected sign-ins create or modify nothing', () => {
  it('rejects a missing ID token', async () => {
    const before = await userCount();
    const res = await signIn({ uid: 'u', email: 'mallory@example.com' });
    assert.equal(res.status, 400);
    assert.equal(res.token, undefined);
    assert.equal(await userCount(), before);
  });

  it('rejects an invalid (unsigned / unknown) token', async () => {
    const before = await userCount();
    const forged = `${b64({ alg: 'RS256' })}.${b64(claimsFor())}.${b64('forged')}`;
    const res = await signIn({ idToken: forged });
    assert.equal(res.status, 401);
    assert.equal(res.token, undefined);
    assert.equal(await userCount(), before);
  });

  it('rejects malformed tokens before calling the verifier', async () => {
    for (const idToken of ['not-a-jwt', 12345, { a: 1 }, 'a.b', 'x'.repeat(5000)]) {
      const res = await signIn({ idToken });
      assert.ok(res.status === 400 || res.status === 401, `status ${res.status} for ${String(idToken).slice(0, 20)}`);
    }
    assert.equal(verifierCalls, 0);
  });

  it('rejects an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const res = await signIn({ idToken: mintToken(claimsFor({ exp: now - 10, iat: now - 4000, auth_time: now - 4000 })) });
    assert.equal(res.status, 401);
  });

  it('rejects a token for a different Firebase project (audience / issuer)', async () => {
    const wrongAud = mintToken(claimsFor({ aud: 'some-other-project' }));
    assert.equal((await signIn({ idToken: wrongAud })).status, 401);
    const wrongIss = mintToken(claimsFor({ iss: 'https://securetoken.google.com/some-other-project' }));
    assert.equal((await signIn({ idToken: wrongIss })).status, 401);
  });

  it('rejects unverified email, non-Google providers and stale sign-ins', async () => {
    const now = Math.floor(Date.now() / 1000);
    const before = await userCount();
    for (const bad of [
      claimsFor({ sub: 'u-unverified', email_verified: false }),
      claimsFor({ sub: 'u-noemail', email: undefined }),
      claimsFor({ sub: 'u-password', firebase: { sign_in_provider: 'password' } }),
      claimsFor({ sub: 'u-anon', firebase: { sign_in_provider: 'anonymous' } }),
      claimsFor({ sub: 'u-stale', auth_time: now - 3600 }),
    ]) {
      const res = await signIn({ idToken: mintToken(bad) });
      assert.equal(res.status, 401, `expected rejection for ${bad.sub}`);
    }
    assert.equal(await userCount(), before);
  });

  it('rejects cross-origin sign-in requests', async () => {
    const res = await signIn({ idToken: mintToken(claimsFor({ sub: 'u-csrf' })) }, { origin: 'https://evil.example' });
    assert.equal(res.status, 403);
  });
});

describe('Accepted sign-ins derive identity from the token only', () => {
  it('signs in with a valid token and issues a session', async () => {
    const res = await signIn({ idToken: mintToken(claimsFor()), intent: 'driver' });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.ok(res.token);
    assert.equal(res.json.user.email, 'alice@example.com');
    assert.equal(res.json.isMasterAdmin, false);
    const who = (await read(await me.GET(request('GET', '/api/auth/me', { token: res.token })))).json.user;
    assert.equal(who.email, 'alice@example.com');
  });

  it('ignores client-supplied uid / email / name / role fields', async () => {
    const res = await signIn({
      idToken: mintToken(claimsFor({ sub: 'google-uid-bob', email: 'bob@example.com', name: 'Bob' })),
      uid: ADMIN_UID,
      email: 'admin@vpark.in',
      name: 'Administrator',
      role: 'ADMIN',
      isMasterAdmin: true,
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.user.email, 'bob@example.com');
    assert.equal(res.json.isMasterAdmin, false);
    assert.ok(!res.json.user.roles.includes('ADMIN'));
    const stored = (await db.getUsers()).find((u) => u.firebaseUid === 'google-uid-bob');
    assert.equal(stored.email, 'bob@example.com');
    assert.ok(!(await db.getUsers()).some((u) => u.firebaseUid === ADMIN_UID && u.email === 'bob@example.com'));
  });

  it('does not take over an account already linked to a different Firebase UID', async () => {
    const res = await signIn({ idToken: mintToken(claimsFor({ sub: 'google-uid-alice-2', email: 'alice@example.com' })) });
    assert.equal(res.status, 200);
    const alice = (await db.getUsers()).find((u) => u.firebaseUid === 'google-uid-alice');
    const alice2 = (await db.getUsers()).find((u) => u.firebaseUid === 'google-uid-alice-2');
    assert.ok(alice && alice2);
    assert.notEqual(alice.id, alice2.id);
  });

  it('an unapproved identity cannot obtain ADMIN, even with an admin-looking email', async () => {
    const res = await signIn({ idToken: mintToken(claimsFor({ sub: 'google-uid-eve', email: 'admin@vpark.in' })) });
    assert.equal(res.status, 200);
    assert.equal(res.json.isMasterAdmin, false);
    assert.ok(!res.json.user.roles.includes('ADMIN'));
    // admin@vpark.in belongs to the seeded legacy admin record; its ADMIN role must not carry over.
    assert.equal((await adminListings.GET(request('GET', '/api/admin/listings', { token: res.token }))).status, 403);
  });

  it('rotates the session on sign-in (the previously presented session is revoked)', async () => {
    const first = await signIn({ idToken: mintToken(claimsFor()) });
    const second = await signIn({ idToken: mintToken(claimsFor()) }, { token: first.token });
    assert.notEqual(first.token, second.token);
    assert.equal((await read(await me.GET(request('GET', '/api/auth/me', { token: first.token })))).json.user, null);
  });
});

describe('Google sign-in lifecycle', () => {
  // Its own client IP, so the per-IP auth rate limit (exercised by the tests above) does not interfere.
  const fromNet = (body) => signIn(body, { headers: { 'x-forwarded-for': '203.0.113.10' } });
  const whoAmI = async (token) => (await read(await me.GET(request('GET', '/api/auth/me', { token })))).json.user;

  it('new driver: onboarding required, then completes; returning sign-in reuses the account', async () => {
    const first = await fromNet({ idToken: mintToken(claimsFor({ sub: 'uid-dan', email: 'dan@example.com' })), intent: 'driver' });
    assert.equal(first.status, 200);
    assert.equal(first.json.onboardingRequired, true);
    const done = await read(await onboarding.POST(request('POST', '/api/auth/onboarding', {
      token: first.token, body: { fullName: 'Dan Driver', phone: '9876543210', acceptTerms: true },
    })));
    assert.equal(done.status, 200, JSON.stringify(done.json));
    assert.equal(done.json.user.phone && done.json.user.roles.includes('DRIVER'), true);
    const users = await userCount();
    const again = await fromNet({ idToken: mintToken(claimsFor({ sub: 'uid-dan', email: 'dan@example.com' })) });
    assert.equal(again.status, 200);
    assert.equal(again.json.user.id, first.json.user.id);
    assert.equal(await userCount(), users, 'a returning user is not duplicated');
  });

  it('new host: provider role and onboarding with a host type', async () => {
    const res = await fromNet({ idToken: mintToken(claimsFor({ sub: 'uid-hana', email: 'hana@example.com' })), intent: 'provider' });
    assert.equal(res.status, 200);
    assert.ok(res.json.user.roles.includes('PROVIDER'));
    const done = await onboarding.POST(request('POST', '/api/auth/onboarding', {
      token: res.token, body: { fullName: 'Hana Host', providerType: 'OWNER', acceptTerms: true },
    }));
    assert.equal(done.status, 200);
  });

  it('an allowlisted Firebase UID is an administrator; others are refused admin routes', async () => {
    const admin = await fromNet({ idToken: mintToken(claimsFor({ sub: ADMIN_UID, email: 'ops@example.com' })) });
    assert.equal(admin.status, 200);
    assert.equal(admin.json.isMasterAdmin, true);
    assert.ok(admin.json.user.roles.includes('ADMIN'));
    assert.equal((await adminListings.GET(request('GET', '/api/admin/listings', { token: admin.token }))).status, 200);
    const user = await fromNet({ idToken: mintToken(claimsFor({ sub: 'uid-not-admin', email: 'ops2@example.com' })) });
    assert.equal(user.json.isMasterAdmin, false);
    assert.equal((await adminListings.GET(request('GET', '/api/admin/listings', { token: user.token }))).status, 403);
  });

  it('logout revokes the session; signing in again issues a fresh one', async () => {
    const first = await fromNet({ idToken: mintToken(claimsFor()) });
    assert.equal((await whoAmI(first.token)).email, 'alice@example.com');
    assert.equal((await logout.POST(request('POST', '/api/auth/logout', { token: first.token }))).status, 200);
    assert.equal(await whoAmI(first.token), null);
    const second = await fromNet({ idToken: mintToken(claimsFor()) });
    assert.equal(second.status, 200);
    assert.equal((await whoAmI(second.token)).email, 'alice@example.com');
  });
});

describe('Verification policy (unit)', () => {
  const env = { FIREBASE_PROJECT_ID: TEST_PROJECT_ID, NODE_ENV: 'test' };

  it('fails closed with 503 when the server is not configured', async () => {
    const r1 = await verifyFirebaseIdToken(mintToken(claimsFor()), { verifier: mockVerifier, env: { NODE_ENV: 'production' } });
    assert.equal(r1.status, 503);
    const r2 = await verifyFirebaseIdToken(mintToken(claimsFor()), { env });
    assert.equal(r2.status, 503);
    const r3 = await verifyFirebaseIdToken(mintToken(claimsFor()), {
      verifier: mockVerifier,
      env: { ...env, NODE_ENV: 'production', FIREBASE_AUTH_EMULATOR_HOST: 'localhost:9099' },
    });
    assert.equal(r3.status, 503, 'the Auth emulator skips signature checks and must be refused in production');
  });

  it('requires a matching uid/sub and well-formed claims', () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    assert.equal(evaluateFirebaseClaims(claimsFor({ uid: 'other' }), { projectId: TEST_PROJECT_ID, nowSeconds }).ok, false);
    assert.equal(evaluateFirebaseClaims(claimsFor({ sub: '' }), { projectId: TEST_PROJECT_ID, nowSeconds }).ok, false);
    assert.equal(evaluateFirebaseClaims(null, { projectId: TEST_PROJECT_ID, nowSeconds }).ok, false);
    assert.equal(evaluateFirebaseClaims(claimsFor(), { projectId: TEST_PROJECT_ID, nowSeconds }).ok, true);
  });
});

describe('Real Firebase Admin SDK verifier (offline rejections)', () => {
  const realVerify = (idToken) =>
    verifyFirebaseIdToken(idToken, {
      verifier: createFirebaseAdminVerifier(),
      env: { FIREBASE_PROJECT_ID: TEST_PROJECT_ID, NODE_ENV: 'test' },
    });

  it('rejects a token issued for another project', async () => {
    const other = claimsFor({ aud: 'some-other-project', iss: 'https://securetoken.google.com/some-other-project' });
    const res = await realVerify(`${b64({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${b64(other)}.${b64('sig')}`);
    assert.equal(res.ok, false);
    assert.equal(res.status, 401);
  });

  it('rejects an unsigned (alg: none) token', async () => {
    const res = await realVerify(`${b64({ alg: 'none', typ: 'JWT' })}.${b64(claimsFor())}.${b64('sig')}`);
    assert.equal(res.ok, false);
    assert.equal(res.status, 401);
  });

  it('rejects garbage that merely looks like a JWT', async () => {
    const res = await realVerify('aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb.cccccccccc');
    assert.equal(res.ok, false);
  });
});

// Sanity: the route module wires the real verifier, not a mock.
describe('Route wiring', () => {
  it('the /api/auth/google route uses the Firebase Admin SDK verifier', async () => {
    const fs = await import('node:fs');
    const src = fs.readFileSync('src/app/api/auth/google/route.ts', 'utf-8');
    assert.ok(src.includes('createFirebaseAdminVerifier()'));
    assert.ok(ORIGIN.startsWith('http'));
  });
});
