/**
 * tests/helpers.js
 *
 * Shared utilities for all test suites:
 *  - DB connect/disconnect against the isolated test database
 *  - Collection cleanup between tests
 *  - Factory helpers to seed users
 *  - Cookie extraction for session-aware request chains
 */

'use strict';

// ─── Set test env vars BEFORE any app module is required ─────────────────────
process.env.NODE_ENV             = 'test';
process.env.SESSION_SECRET       = 'test-session-secret-32-chars-min!!';
process.env.JWT_SECRET           = 'test-jwt-secret-32-chars-minimum!!';
process.env.MONGO_URI            = 'mongodb://127.0.0.1:27017/auth-server-test';
process.env.CLIENT_ID            = 'client-app-1';
process.env.CLIENT_SECRET        = 'test-client-secret';
process.env.ALLOWED_REDIRECT_URIS = 'http://localhost:3001/callback';
process.env.ALLOWED_ORIGINS      = 'http://localhost:3001';

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const User     = require('../models/User');

// ─── OAuth test fixtures ──────────────────────────────────────────────────────
const OAUTH_PARAMS = {
  client_id:     'client-app-1',
  redirect_uri:  'http://localhost:3001/callback',
  state:         'test-csrf-state-abc123',
  response_type: 'code',
};

// ─── DB lifecycle ─────────────────────────────────────────────────────────────
const connectTestDB = async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect('mongodb://127.0.0.1:27017/auth-server-test');
  }
};

const disconnectTestDB = async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
};

const clearCollections = async () => {
  const { collections } = mongoose.connection;
  await Promise.all(Object.values(collections).map((c) => c.deleteMany({})));
};

// ─── User factory ─────────────────────────────────────────────────────────────
const createTestUser = async (overrides = {}) => {
  const defaults = {
    username: 'testuser',
    email:    'test@example.com',
    password: await bcrypt.hash('Password123', 10),
  };
  return User.create({ ...defaults, ...overrides });
};

// ─── Cookie helper ────────────────────────────────────────────────────────────
// Extracts name=value pairs from Set-Cookie response headers so they can be
// re-sent in a Cookie request header, simulating a real browser session chain.
const extractCookies = (headers) => {
  const setCookie = headers['set-cookie'] || [];
  return setCookie.map((c) => c.split(';')[0]).join('; ');
};

module.exports = {
  OAUTH_PARAMS,
  connectTestDB,
  disconnectTestDB,
  clearCollections,
  createTestUser,
  extractCookies,
};
