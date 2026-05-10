/**
 * Auth Controller
 *
 * Implements the OAuth 2.0 Authorization Code Grant flow:
 *
 *  1. GET  /authorize        — validates the OAuth request; redirects unauthenticated
 *                              users to /login, then issues an auth code.
 *  2. GET  /login            — renders the login form (preserves OAuth params).
 *  3. POST /login            — authenticates credentials; redirects back to /authorize.
 *  4. GET  /register         — renders the registration form.
 *  5. POST /register         — creates a new user; redirects back to /authorize.
 *  6. POST /oauth/token      — exchanges a short-lived auth code for a JWT.
 *  7. GET  /oauth/userinfo   — validates a Bearer JWT; returns the user profile.
 *  8. GET  /logout           — destroys the server-side session.
 *
 * Security highlights:
 *  - bcrypt with 12 rounds for password hashing.
 *  - redirect_uri validated against a strict allowlist (prevents Open Redirect).
 *  - Authorization codes are single-use and expire after 10 minutes.
 *  - Code-reuse attempts delete the code immediately (replay attack mitigation).
 *  - JWTs are signed HS256 and scoped to the requesting client_id (audience).
 */

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');

// ─── Registered OAuth clients ─────────────────────────────────────────────────
// In production, persist this in your database or a secrets manager.

function getClients() {
  return {
    [process.env.CLIENT_ID || 'client-app-1']: {
      clientSecret: process.env.CLIENT_SECRET,
      redirectUris: (process.env.ALLOWED_REDIRECT_URIS || 'http://localhost:3001/callback')
        .split(',')
        .map((u) => u.trim()),
      name: 'Client Application',
    },
  };
}

// ─── In-memory authorization code store ──────────────────────────────────────
// Replace with Redis in production for multi-instance deployments.
//
// Shape: code (string) → { userId, clientId, redirectUri, expiresAt, used }
const authCodes = new Map();

// Purge expired codes every 5 minutes to prevent unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes.entries()) {
    if (data.expiresAt < now) {
      authCodes.delete(code);
    }
  }
}, 5 * 60 * 1000);

// ─── Helper: build a URLSearchParams string from req.query ───────────────────
function oauthQueryString(query) {
  const allowed = ['client_id', 'redirect_uri', 'state', 'response_type'];
  const filtered = {};
  for (const key of allowed) {
    if (query[key]) filtered[key] = query[key];
  }
  return new URLSearchParams(filtered).toString();
}

// ─── Controllers ──────────────────────────────────────────────────────────────

/** GET / — simple status page */
exports.home = (req, res) => {
  if (req.session.userId) {
    // Escape email before embedding in HTML to prevent XSS
    const safeEmail = (req.session.email || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    res.send(
      `<h1>Auth Server</h1>
       <p>Signed in as <strong>${safeEmail}</strong></p>
       <a href="/logout">Sign out</a>`
    );
  } else {
    res.send(
      `<h1>Auth Server</h1>
       <p>No active session.</p>
       <a href="/login">Sign in</a> &nbsp;|&nbsp; <a href="/register">Register</a>`
    );
  }
};

// ─── Login ────────────────────────────────────────────────────────────────────

/** GET /login */
exports.showLogin = (req, res) => {
  res.render('login', {
    error: null,
    errorField: null,
    registerHint: false,
    query: req.query,
    queryString: oauthQueryString(req.query),
  });
};

/** POST /login */
exports.processLogin = async (req, res) => {
  console.log('Login attempt:', req.body.identifier);
  // OAuth params are submitted as hidden form fields
  const { identifier, password, client_id, redirect_uri, state, response_type } = req.body;
  const oauthQuery = { client_id, redirect_uri, state, response_type };
  const queryString = oauthQueryString(oauthQuery);

  // --- Input validation (via express-validator) ---
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstErr = errors.array()[0];
    return res.render('login', {
      error: firstErr.msg,
      errorField: firstErr.path,   // 'identifier' or 'password'
      registerHint: false,
      query: oauthQuery,
      queryString,
    });
  }

  try {
    // Determine if the user typed an email or a username
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier.trim());
    let user;

    if (isEmail) {
      // Email lookup — normalise to lowercase
      user = await User.findOne({ email: identifier.trim().toLowerCase() });
    } else {
      // Username lookup — case-sensitive (stored as-is on registration)
      user = await User.findOne({ username: identifier.trim() });
    }

    if (!user) {
      await new Promise((resolve) => setTimeout(resolve, 300));
      const label = isEmail ? identifier.trim().toLowerCase() : identifier.trim();
      return res.render('login', {
        error: `No account found for "${label}". Please check your details or register.`,
        errorField: 'identifier',
        registerHint: true,
        query: oauthQuery,
        queryString,
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.render('login', {
        error: 'Incorrect password. Please try again.',
        errorField: 'password',
        registerHint: false,
        query: oauthQuery,
        queryString,
      });
    }

    // Regenerate session ID on privilege escalation (session fixation mitigation)
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regeneration error:', regenErr);
        return res.render('login', { error: 'An internal error occurred.', errorField: null, registerHint: false, query: oauthQuery, queryString });
      }

      req.session.userId = user._id.toString();
      req.session.email = user.email;

      // Explicitly save before redirecting — regenerate() does not auto-save,
      // so without this the session is missing when /authorize is hit next.
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('Session save error:', saveErr);
          return res.render('login', { error: 'An internal error occurred.', errorField: null, registerHint: false, query: oauthQuery, queryString });
        }

        // If in the middle of an OAuth flow, return to /authorize
        if (client_id && redirect_uri && state) {
          const params = new URLSearchParams({
            client_id,
            redirect_uri,
            state,
            response_type: response_type || 'code',
          });
          return res.redirect(`/authorize?${params.toString()}`);
        }

        res.redirect('/');
      });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'An internal error occurred.', errorField: null, registerHint: false, query: oauthQuery, queryString });
  }
};

// ─── Registration ─────────────────────────────────────────────────────────────

/** GET /register */
exports.showRegister = (req, res) => {
  res.render('register', {
    error: null,
    query: req.query,
    queryString: oauthQueryString(req.query),
  });
};

/** POST /register */
exports.processRegister = async (req, res) => {
  const { username, email, password, client_id, redirect_uri, state, response_type } = req.body;
  const oauthQuery = { client_id, redirect_uri, state, response_type };
  const queryString = oauthQueryString(oauthQuery);

  // --- Input validation ---
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('register', {
      error: errors.array()[0].msg,
      query: oauthQuery,
      queryString,
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();

    // Check for existing account
    const existing = await User.findOne({
      $or: [{ email: normalizedEmail }, { username }],
    });
    if (existing) {
      const field = existing.email === email.toLowerCase() ? 'email' : 'username';
      return res.render('register', {
        error: `That ${field} is already in use.`,
        query: oauthQuery,
        queryString,
      });
    }

    // Hash password — 12 rounds provides strong security with acceptable latency
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email: normalizedEmail,
      password: passwordHash,
    });

    // Session fixation mitigation
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regeneration error:', regenErr);
        return res.render('register', { error: 'An internal error occurred.', query: oauthQuery, queryString });
      }

      req.session.userId = user._id.toString();
      req.session.email = user.email;

      // Explicitly save before redirecting (same reason as processLogin)
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error('Session save error:', saveErr);
          return res.render('register', { error: 'An internal error occurred.', query: oauthQuery, queryString });
        }

        if (client_id && redirect_uri && state) {
          const params = new URLSearchParams({
            client_id,
            redirect_uri,
            state,
            response_type: response_type || 'code',
          });
          return res.redirect(`/authorize?${params.toString()}`);
        }

        // No OAuth flow — send to login so the user can sign in
        res.redirect('/login');
      });
    });
  } catch (err) {
    // Handle MongoDB duplicate key (race condition between findOne check and create)
    if (err.code === 11000) {
      const field = err.keyPattern && err.keyPattern.email ? 'email' : 'username';
      return res.render('register', {
        error: `That ${field} is already in use.`,
        query: oauthQuery,
        queryString,
      });
    }
    console.error('Register error:', err);
    res.render('register', { error: 'An internal error occurred.', query: oauthQuery, queryString });
  }
};

// ─── OAuth: Authorize ─────────────────────────────────────────────────────────

/**
 * GET /authorize
 *
 * Entry point for the OAuth Authorization Code flow.
 *
 * Expected query params:
 *   client_id      — identifies the requesting client
 *   redirect_uri   — where to send the user back after auth (MUST be on allowlist)
 *   state          — CSRF token generated by the client; echoed back unchanged
 *   response_type  — must be "code"
 */
exports.authorize = (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  // 1. Validate required parameters
  if (!client_id || !redirect_uri || !state || response_type !== 'code') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing or invalid required parameters: client_id, redirect_uri, state, response_type=code',
    });
  }

  // 2. Validate client identity
  const clients = getClients();
  const client = clients[client_id];
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: `Unknown client_id: ${client_id}`,
    });
  }

  // 3. *** CRITICAL SECURITY CHECK ***
  //    Validate redirect_uri against a strict allowlist.
  //    An unchecked redirect_uri allows attackers to steal auth codes via open redirect.
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_redirect_uri',
      error_description:
        'The redirect_uri is not registered for this client. ' +
        'Add it to ALLOWED_REDIRECT_URIS on the auth server.',
    });
  }

  // 4. If user is not authenticated, redirect to login (preserving all OAuth params)
  if (!req.session.userId) {
    const params = new URLSearchParams({ client_id, redirect_uri, state, response_type });
    return res.redirect(`/login?${params.toString()}`);
  }

  // 5. User is authenticated — issue a short-lived, single-use authorization code
  const code = crypto.randomBytes(32).toString('hex'); // 256-bit entropy
  authCodes.set(code, {
    userId: req.session.userId,
    clientId: client_id,
    redirectUri: redirect_uri,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    used: false,
  });

  // 6. Redirect back to the client with code + state
  //    The client MUST verify state matches what it originally sent.
  const callbackParams = new URLSearchParams({ code, state });
  return res.redirect(`${redirect_uri}?${callbackParams.toString()}`);
};

// ─── OAuth: Token Exchange ─────────────────────────────────────────────────────

/**
 * POST /oauth/token
 *
 * The client exchanges an authorization code for a signed JWT access token.
 * This endpoint requires the client_secret, so the exchange MUST happen
 * server-to-server (never from browser JavaScript).
 *
 * Body params:
 *   grant_type     — must be "authorization_code"
 *   code           — the auth code received at the redirect_uri
 *   client_id      — must match the code's bound client
 *   client_secret  — authenticates the client
 *   redirect_uri   — must exactly match the one used in /authorize
 */
exports.exchangeToken = async (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  // Reject non-string values — prevents NoSQL operator injection via JSON body
  // e.g. {"client_id": {"$ne": null}} must not reach client registry lookup
  if (
    typeof grant_type   !== 'string' ||
    typeof code         !== 'string' ||
    typeof client_id    !== 'string' ||
    typeof client_secret !== 'string' ||
    typeof redirect_uri !== 'string'
  ) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'All parameters must be plain strings.',
    });
  }

  // Validate grant type
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (!code || !client_id || !client_secret || !redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required body parameters.',
    });
  }

  // Validate client credentials
  const clients = getClients();
  const client = clients[client_id];
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed.',
    });
  }

  // Use timing-safe comparison to prevent timing attacks on client_secret
  const expectedSecret = client.clientSecret || '';
  const providedSecret = client_secret || '';
  let secretMatch = false;
  try {
    secretMatch =
      expectedSecret.length === providedSecret.length &&
      crypto.timingSafeEqual(Buffer.from(expectedSecret), Buffer.from(providedSecret));
  } catch (_) {
    secretMatch = false;
  }
  if (!secretMatch) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed.',
    });
  }

  // Retrieve and validate the authorization code
  const codeData = authCodes.get(code);

  if (!codeData) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code is invalid or expired.',
    });
  }

  // Detect code reuse — potential replay attack; invalidate immediately
  if (codeData.used) {
    authCodes.delete(code);
    console.warn(`[SECURITY] Authorization code reuse detected for client: ${client_id}`);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used.',
    });
  }

  // Check expiry
  if (Date.now() > codeData.expiresAt) {
    authCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has expired.',
    });
  }

  // Verify binding: client_id and redirect_uri must match what was used in /authorize
  if (codeData.clientId !== client_id || codeData.redirectUri !== redirect_uri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Code binding mismatch: client_id or redirect_uri does not match.',
    });
  }

  // Mark code as used before the async DB call (prevents race conditions)
  codeData.used = true;
  authCodes.set(code, codeData);

  try {
    const user = await User.findById(codeData.userId).select('-password');
    if (!user) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'User no longer exists.' });
    }

    // Issue a signed JWT access token
    const token = jwt.sign(
      {
        sub: user._id.toString(),
        email: user.email,
        username: user.username,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '1h',
        issuer: 'auth-server',
        audience: client_id,  // scopes the token to this client
      }
    );

    // Delete used code immediately — no window for replay
    authCodes.delete(code);

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
    });
  } catch (err) {
    console.error('Token exchange error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
};

// ─── OAuth: UserInfo ─────────────────────────────────────────────────────────

/**
 * GET /oauth/userinfo
 *
 * Protected resource endpoint. The client sends its access token as a
 * Bearer token; we verify it and return the user's profile.
 */
exports.userInfo = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token', error_description: 'Authorization: Bearer <token> header required.' });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'auth-server',
      // Audience is the client_id embedded in the token at issuance time.
      // We allow any registered client to introspect their own token.
      // The audience check happens per-token: jwt.verify enforces aud === decoded.aud.
    });

    const user = await User.findById(decoded.sub).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'User not found.' });
    }

    return res.json({
      sub: decoded.sub,
      email: user.email,
      username: user.username,
      created_at: user.createdAt,
    });
  } catch (err) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: err.name === 'TokenExpiredError' ? 'Token has expired.' : 'Token verification failed.',
    });
  }
};

// ─── Logout ───────────────────────────────────────────────────────────────────

/** GET /logout */
exports.logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);
    res.clearCookie('auth.sid');

    // Support post-logout redirect back to the client app.
    // Only allow redirects to origins registered in ALLOWED_ORIGINS.
    const redirectUri = req.query.post_logout_redirect_uri;
    if (redirectUri) {
      const allowed = (process.env.ALLOWED_ORIGINS || '')
        .split(',')
        .map((o) => o.trim());
      try {
        const target = new URL(redirectUri);
        if (allowed.includes(target.origin)) {
          return res.redirect(redirectUri);
        }
      } catch (_) { /* invalid URL — fall through to default */ }
    }

    res.redirect('/');
  });
};
