/**
 * tests/registration.test.js
 *
 * Tests for POST /register:
 *  ✓ valid data saves user to DB
 *  ✓ valid data sets session userId
 *  ✓ with OAuth params → redirects to /authorize (continues flow)
 *  ✓ without OAuth params → redirects to /login
 *  ✗ duplicate email shows error
 *  ✗ duplicate username shows error
 *  ✗ password too short shows error
 *  ✗ passwords do not match shows error
 *  ✗ invalid username characters shows error
 */

'use strict';

const request = require('supertest');
const {
  connectTestDB, disconnectTestDB, clearCollections,
  createTestUser, extractCookies, OAUTH_PARAMS,
} = require('./helpers');

// helpers.js sets process.env — import app AFTER helpers
const app  = require('../app');
const User = require('../models/User');

beforeAll(connectTestDB);
afterAll(disconnectTestDB);
afterEach(clearCollections);

// ─── Valid registration ───────────────────────────────────────────────────────

test('saves new user to the database', async () => {
  await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  const user = await User.findOne({ email: 'alice@example.com' });
  expect(user).not.toBeNull();
  expect(user.username).toBe('alice');
});

test('does not store plaintext password', async () => {
  await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  const user = await User.findOne({ email: 'alice@example.com' });
  expect(user.password).not.toBe('Password123');
  // bcryptjs 2.4.x produces $2a$ hashes; newer bcrypt uses $2b$ — match both
  expect(user.password).toMatch(/^\$2[ab]\$\d+\$/);
});

test('without OAuth params redirects to /login', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toBe('/login');
});

test('with OAuth params redirects to /authorize', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
    ...OAUTH_PARAMS,
  });

  expect(res.status).toBe(302);
  expect(res.headers.location).toMatch(/^\/authorize\?/);
  expect(res.headers.location).toContain('client_id=client-app-1');
  expect(res.headers.location).toContain(`state=${OAUTH_PARAMS.state}`);
});

test('session cookie is set after successful registration', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  expect(res.headers['set-cookie']).toBeDefined();
  const cookies = res.headers['set-cookie'].join('');
  expect(cookies).toContain('auth.sid');
});

// ─── KEY TEST: session is saved before redirect (the regenerate bug) ──────────
test('session persists into /authorize after registration redirect', async () => {
  const registerRes = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
    ...OAUTH_PARAMS,
  });

  expect(registerRes.status).toBe(302);
  const cookies = extractCookies(registerRes.headers);

  // Follow the redirect to /authorize with the session cookie.
  // If session.save() is missing, /authorize won't see the userId and will
  // redirect back to /login instead of issuing the auth code.
  const authorizeRes = await request(app)
    .get('/authorize')
    .set('Cookie', cookies)
    .query(OAUTH_PARAMS);

  expect(authorizeRes.status).toBe(302);
  expect(authorizeRes.headers.location).toMatch(/^http:\/\/localhost:3001\/callback\?code=/);
  expect(authorizeRes.headers.location).toContain(`state=${OAUTH_PARAMS.state}`);
});

// ─── Validation errors ────────────────────────────────────────────────────────

test('duplicate email returns 200 with error message', async () => {
  await createTestUser({ username: 'existing', email: 'taken@example.com' });

  const res = await request(app).post('/register').type('form').send({
    username: 'newuser', email: 'taken@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('email');
});

test('duplicate username returns 200 with error message', async () => {
  await createTestUser({ username: 'takenuser', email: 'other@example.com' });

  const res = await request(app).post('/register').type('form').send({
    username: 'takenuser', email: 'new@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('username');
});

test('password shorter than 8 characters returns validation error', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'short', confirmPassword: 'short',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('8 characters');
});

test('mismatched passwords returns validation error', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Different123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('match');
});

test('invalid username characters returns validation error', async () => {
  const res = await request(app).post('/register').type('form').send({
    username: 'alice@#$', email: 'alice@example.com',
    password: 'Password123', confirmPassword: 'Password123',
  });

  expect(res.status).toBe(200);
  expect(res.text).toContain('username');
});
