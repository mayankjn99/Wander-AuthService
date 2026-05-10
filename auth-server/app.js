/**
 * app.js — Express application factory
 *
 * Separated from server.js so the app can be imported in tests
 * without triggering a MongoDB connection or port binding.
 */

'use strict';

const express  = require('express');
const session  = require('express-session');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');
const cors     = require('cors');
const path     = require('path');

const authRoutes = require('./routes/authRoutes');

const app = express();

// ─── Security Headers ─────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:              ["'self'"],
        styleSrc:                ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
        scriptSrc:               ["'self'", 'https://cdn.tailwindcss.com'],
        imgSrc:                  ["'self'", 'data:'],
        fontSrc:                 ["'self'"],
        // form-action 'self' causes Chrome to block submissions on localhost when
        // two services share the hostname (different ports). The forms use relative
        // action paths (/login, /register) so same-origin is already enforced by
        // the browser without this directive.
        formAction:              null,
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
    hsts: process.env.NODE_ENV === 'production'
      ? { maxAge: 31536000, includeSubDomains: true }
      : false,
  })
);

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// Disabled in test environment so test suites don't get throttled
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'test' ? 10_000 : 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'rate_limit_exceeded', error_description: 'Too many requests.' },
  })
);

// ─── Body Parsers ─────────────────────────────────────────────────────────────
// Limit body size to prevent DoS via large payloads
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─── CORS (scoped to /oauth endpoints only) ───────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3001')
  .split(',')
  .map((o) => o.trim());

app.use(
  '/oauth',
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error(`CORS: origin ${origin} not allowed`));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
  })
);

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(
  session({
    name: 'auth.sid',          // distinct name — prevents collision with client app's cookie
    secret: process.env.SESSION_SECRET || 'fallback-test-secret',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// ─── Static files ─────────────────────────────────────────────────────────────
// Serves /public — JS validation bundle is loaded from here (keeps CSP clean)
app.use(express.static(path.join(__dirname, 'public')));

// ─── View Engine ──────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/', authRoutes);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'not_found' });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'server_error' });
});

module.exports = app;
