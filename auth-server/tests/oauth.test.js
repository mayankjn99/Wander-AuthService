/**
 * tests/oauth.test.js
 *
 * Tests for the full OAuth 2.0 Authorization Code flow:
 *
 *  /authorize
 *  ✓ unauthenticated → redirects to /login preserving all OAuth params
 *  ✓ authenticated → issues code + redirects to callback with state
 *  ✗ missing client_id → 400
 *  ✗ missing state → 400
 *  ✗ unregistered redirect_uri → 400 (Open Redirect guard)
 *  ✗ unknown client_id → 400
 *
 *  /oauth/token
 *  ✓ valid code exchange → returns JWT + token_type + expires_in
 *  ✓ JWT contains expected claims (sub, email, username)
 *  ✗ expired code → 400 invalid_grant
 *  ✗ reused code → 400 (replay attack prevention)
 *  ✗ wrong client_secret → 401
 *  ✗ redirect_uri mismatch → 400
 *
 *  /oauth/userinfo
 *  ✓ valid Bearer token → returns user profile
 *  ✗ missing token → 401
 *  ✗ tampered token → 401
 *
 *  Integration
 *  ✓ full flow: register → authorize → token exchange → userinfo
 */

'use strict';

const request = require('supertest');
const jwt     = require('jsonwebtoken');
const {
  connectTestDB, disconnectTestDB, clearCollections,
  createTestUser, extractCookies, OAUTH_PARAMS,
} = require('./helpers');

const app = require('../app');

beforeAll(connectTestDB);
afterAll(disconnectTestDB);
afterEach(clearCollections);

// ─── Helper: get an authenticated session cookie ──────────────────────────────
const loginAndGetCookies = async () => {
  await createTestUser();
  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'Password123',
    ...OAUTH_PARAMS,
  });
  return extractCookies(res.headers);
};

// ─── /authorize ───────────────────────────────────────────────────────────────

describe('GET /authorize', () => {
  test('unauthenticated user is redirected to /login', async () => {
    const res = await request(app).get('/authorize').query(OAUTH_PARAMS);

    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^\/login\?/);
  });

  test('redirects to /login preserving all OAuth params', async () => {
    const res = await request(app).get('/authorize').query(OAUTH_PARAMS);

    const loc = res.headers.location;
    expect(loc).toContain('client_id=client-app-1');
    expect(loc).toContain('redirect_uri=');
    expect(loc).toContain(`state=${OAUTH_PARAMS.state}`);
    expect(loc).toContain('response_type=code');
  });

  test('authenticated user receives auth code redirect to callback', async () => {
    const cookies = await loginAndGetCookies();

    const res = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query(OAUTH_PARAMS);

    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^http:\/\/localhost:3001\/callback\?code=/);
  });

  test('state is echoed back unchanged in the callback redirect', async () => {
    const cookies = await loginAndGetCookies();

    const res = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query(OAUTH_PARAMS);

    expect(res.headers.location).toContain(`state=${OAUTH_PARAMS.state}`);
  });

  test('missing state param returns 400', async () => {
    const cookies = await loginAndGetCookies();
    const { state: _s, ...paramsWithoutState } = OAUTH_PARAMS;

    const res = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query(paramsWithoutState);

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  test('unknown client_id returns 400', async () => {
    const cookies = await loginAndGetCookies();

    const res = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query({ ...OAUTH_PARAMS, client_id: 'unknown-client' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
  });

  test('unregistered redirect_uri returns 400 (Open Redirect guard)', async () => {
    const cookies = await loginAndGetCookies();

    const res = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query({ ...OAUTH_PARAMS, redirect_uri: 'https://evil.com/steal' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
  });
});

// ─── /oauth/token ─────────────────────────────────────────────────────────────

// Helper: complete authorize step and extract the code from the redirect URL
const getAuthCode = async () => {
  const cookies = await loginAndGetCookies();
  const res = await request(app)
    .get('/authorize')
    .set('Cookie', cookies)
    .query(OAUTH_PARAMS);

  const url    = new URL(res.headers.location, 'http://localhost:3000');
  return url.searchParams.get('code');
};

describe('POST /oauth/token', () => {
  test('valid code returns access_token, token_type, expires_in', async () => {
    const code = await getAuthCode();

    const res = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeDefined();
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.expires_in).toBe(3600);
  });

  test('access_token is a valid JWT with correct claims', async () => {
    const code = await getAuthCode();

    const res = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });

    const decoded = jwt.verify(res.body.access_token, process.env.JWT_SECRET);
    expect(decoded.email).toBe('test@example.com');
    expect(decoded.username).toBe('testuser');
    expect(decoded.sub).toBeDefined();
    expect(decoded.iss).toBe('auth-server');
    expect(decoded.aud).toBe('client-app-1');
  });

  test('reusing the same code returns 400 (replay attack prevention)', async () => {
    const code = await getAuthCode();
    const tokenBody = {
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    };

    // First use — should succeed
    const first = await request(app).post('/oauth/token').send(tokenBody);
    expect(first.status).toBe(200);

    // Second use of same code — must be rejected
    const second = await request(app).post('/oauth/token').send(tokenBody);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe('invalid_grant');
  });

  test('wrong client_secret returns 401', async () => {
    const code = await getAuthCode();

    const res = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'wrong-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  test('redirect_uri mismatch returns 400', async () => {
    const code = await getAuthCode();

    const res = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/wrong-path',
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  test('invalid code returns 400', async () => {
    const res = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code:          'totally-fake-code-that-does-not-exist',
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });
});

// ─── /oauth/userinfo ──────────────────────────────────────────────────────────

describe('GET /oauth/userinfo', () => {
  test('valid Bearer token returns user profile', async () => {
    const code = await getAuthCode();

    const tokenRes = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${tokenRes.body.access_token}`);

    expect(res.status).toBe(200);
    expect(res.body.email).toBe('test@example.com');
    expect(res.body.username).toBe('testuser');
    expect(res.body.sub).toBeDefined();
  });

  test('missing Authorization header returns 401', async () => {
    const res = await request(app).get('/oauth/userinfo');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('missing_token');
  });

  test('tampered JWT returns 401', async () => {
    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalidsig');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });
});

// ─── Full integration flow ────────────────────────────────────────────────────

describe('Full OAuth flow: register → authorize → token → userinfo', () => {
  test('completes end-to-end without errors', async () => {
    // 1. Register
    const registerRes = await request(app).post('/register').type('form').send({
      username: 'flowuser', email: 'flow@example.com',
      password: 'Password123', confirmPassword: 'Password123',
      ...OAUTH_PARAMS,
    });
    expect(registerRes.status).toBe(302);
    const cookies = extractCookies(registerRes.headers);

    // 2. Authorize — session must be saved (tests session.save() fix)
    const authorizeRes = await request(app)
      .get('/authorize')
      .set('Cookie', cookies)
      .query(OAUTH_PARAMS);
    expect(authorizeRes.status).toBe(302);

    const callbackUrl = new URL(authorizeRes.headers.location);
    const code  = callbackUrl.searchParams.get('code');
    const state = callbackUrl.searchParams.get('state');
    expect(code).toBeTruthy();
    expect(state).toBe(OAUTH_PARAMS.state);

    // 3. Token exchange
    const tokenRes = await request(app).post('/oauth/token').send({
      grant_type:    'authorization_code',
      code,
      client_id:     'client-app-1',
      client_secret: 'test-client-secret',
      redirect_uri:  'http://localhost:3001/callback',
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.access_token).toBeTruthy();

    // 4. Userinfo
    const userinfoRes = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${tokenRes.body.access_token}`);
    expect(userinfoRes.status).toBe(200);
    expect(userinfoRes.body.email).toBe('flow@example.com');
    expect(userinfoRes.body.username).toBe('flowuser');
  });
});
