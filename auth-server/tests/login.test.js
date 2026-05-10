/**
 * tests/login.test.js
 *
 * Tests for POST /login:
 *  ✓ login with email — correct credentials redirects correctly
 *  ✓ login with username — correct credentials redirects correctly
 *  ✓ with OAuth params → session saved → redirect reaches /authorize
 *  ✓ session cookie set after successful login
 *  ✓ previous failed attempt does not persist error on next request
 *  ✗ unknown email → 200 with register hint
 *  ✗ unknown username → 200 with register hint
 *  ✗ wrong password → 200 with "Incorrect password" message
 *  ✗ invalid identifier (neither email nor username format) → 200 with validation error
 *  ✗ missing password → 200 with validation error
 */

'use strict';

const request = require('supertest');
const {
  connectTestDB, disconnectTestDB, clearCollections,
  createTestUser, extractCookies, OAUTH_PARAMS,
} = require('./helpers');

const app = require('../app');

beforeAll(connectTestDB);
afterAll(disconnectTestDB);
afterEach(clearCollections);

// ─── Successful login — by email ──────────────────────────────────────────────

test('valid email + password without OAuth params redirects to /', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'Password123',
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toBe('/');
});

test('session cookie is set after successful login with email', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'Password123',
  });

  expect(res.headers['set-cookie']).toBeDefined();
  expect(res.headers['set-cookie'].join('')).toContain('auth.sid');
});

// ─── Successful login — by username ───────────────────────────────────────────

test('valid username + password without OAuth params redirects to /', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'testuser',
    password: 'Password123',
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toBe('/');
});

test('session cookie is set after successful login with username', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'testuser',
    password: 'Password123',
  });

  expect(res.headers['set-cookie']).toBeDefined();
  expect(res.headers['set-cookie'].join('')).toContain('auth.sid');
});

// ─── OAuth flow ───────────────────────────────────────────────────────────────

test('valid credentials with OAuth params redirects to /authorize', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'Password123',
    ...OAUTH_PARAMS,
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toMatch(/^\/authorize\?/);
  expect(res.headers.location).toContain('client_id=client-app-1');
});

test('username login with OAuth params redirects to /authorize', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'testuser',
    password: 'Password123',
    ...OAUTH_PARAMS,
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toMatch(/^\/authorize\?/);
});

// ─── KEY TEST: session.save() before redirect ─────────────────────────────────

test('session persists into /authorize after login redirect (session.save bug)', async () => {
  await createTestUser();

  const loginRes = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'Password123',
    ...OAUTH_PARAMS,
  });

  expect(loginRes.status).toBe(302);
  expect(loginRes.headers.location).toMatch(/\/authorize/);

  const cookies = extractCookies(loginRes.headers);
  expect(cookies).toBeTruthy();

  const authorizeRes = await request(app)
    .get('/authorize')
    .set('Cookie', cookies)
    .query(OAUTH_PARAMS);

  expect(authorizeRes.status).toBe(302);
  expect(authorizeRes.headers.location).toMatch(
    /^http:\/\/localhost:3001\/callback\?code=[a-f0-9]+&state=test-csrf-state-abc123$/
  );
});

// ─── Error isolation ──────────────────────────────────────────────────────────

test('failed login does not persist error to the next login page GET', async () => {
  await createTestUser();

  const failedRes = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'WrongPassword!',
  });
  expect(failedRes.status).toBe(200);
  expect(failedRes.text).toContain('Incorrect password');

  const freshRes = await request(app).get('/login');
  expect(freshRes.status).toBe(200);
  expect(freshRes.text).not.toContain('Incorrect password');
  expect(freshRes.text).not.toContain('Invalid');
});

test('multiple failed attempts do not bleed into each other', async () => {
  await createTestUser();

  const res1 = await request(app).post('/login').type('form').send({
    identifier: 'nobody@example.com',
    password: 'Password123',
  });
  expect(res1.text).toContain('No account found');

  const res2 = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'WrongPassword!',
  });
  expect(res2.text).not.toContain('No account found');
  expect(res2.text).toContain('Incorrect password');
});

// ─── Error cases ──────────────────────────────────────────────────────────────

test('unknown email returns 200 with register hint', async () => {
  const res = await request(app).post('/login').type('form').send({
    identifier: 'ghost@example.com',
    password: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('No account found');
  expect(res.text).toContain('/register');
});

test('unknown username returns 200 with register hint', async () => {
  const res = await request(app).post('/login').type('form').send({
    identifier: 'ghostuser',
    password: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('No account found');
  expect(res.text).toContain('/register');
});

test('wrong password returns 200 with incorrect password message', async () => {
  await createTestUser();

  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'WrongPassword!',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('Incorrect password');
  expect(res.text).not.toContain('No account found');
});

test('invalid identifier (not email or username format) returns 200 with validation error', async () => {
  // "not-an-email" contains hyphens → not a valid username (/^[a-zA-Z0-9_]+$/)
  // and is not a valid email → fails both checks
  const res = await request(app).post('/login').type('form').send({
    identifier: 'not-an-email',
    password: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('valid email address or username');
});

test('password under 8 chars returns 200 with validation error', async () => {
  const res = await request(app).post('/login').type('form').send({
    identifier: 'test@example.com',
    password: 'short',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('8 characters');
});
