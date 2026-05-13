/**
 * Client App Server
 *
 * A minimal Express back-end that acts as a confidential OAuth 2.0 client.
 *
 * Why a server?
 *   The Authorization Code flow requires a `client_secret` to exchange the
 *   auth code for a JWT. Exposing the secret in browser JS is insecure.
 *   This server acts as a Backend-for-Frontend (BFF): it keeps the secret
 *   and access token server-side, only sharing a session cookie with the browser.
 *
 * Flow:
 *   1. Browser visits /login
 *      → server generates a random `state`, saves it to session
 *      → server redirects browser to Auth Server /authorize
 *
 *   2. Auth Server authenticates the user and redirects browser to /callback?code=X&state=Y
 *
 *   3. Browser hits /callback
 *      → server verifies `state` matches (CSRF check)
 *      → server POSTs code to Auth Server /oauth/token  (server-to-server)
 *      → server stores JWT in session (never sent to browser)
 *      → browser is redirected to /dashboard
 *
 *   4. Browser hits /api/me  (called by dashboard.html via fetch)
 *      → server calls Auth Server /oauth/userinfo with Bearer token
 *      → returns user profile JSON to browser
 */

'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto  = require('crypto');
const path    = require('path');

const app = express();

// Trust Render's reverse proxy so secure session cookies work on HTTPS
app.set('trust proxy', 1);

// ─── Config ───────────────────────────────────────────────────────────────────
const AUTH_SERVER  = (process.env.AUTH_SERVER_URL || 'http://localhost:3000').replace(/\/$/, '');
const CLIENT_ID    = process.env.CLIENT_ID    || 'client-app-1';
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3001/callback';
const PORT         = process.env.PORT         || 3001;

if (!CLIENT_SECRET) {
  console.error('FATAL: CLIENT_SECRET is not set.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set.');
  process.exit(1);
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    name: 'client.sid',        // distinct name — prevents collision with auth server's cookie
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000, // 1 hour (matches JWT expiry)
    },
  })
);

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /login
 * Initiates the OAuth Authorization Code flow.
 * Generates a cryptographically random `state` value to prevent CSRF.
 */
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  // Persist state in session — verified in /callback
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id:     CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    state,
    response_type: 'code',
  });

  res.redirect(`${AUTH_SERVER}/authorize?${params.toString()}`);
});

/**
 * GET /register
 * Initiates the OAuth flow but drops the user directly on the auth server's
 * registration page instead of the login page. The state is generated here
 * so the CSRF check in /callback still works exactly the same way.
 */
app.get('/register', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id:     CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    state,
    response_type: 'code',
  });

  // Go straight to the register form — OAuth params are passed as query string
  // so they survive as hidden fields on the form and are echoed back after
  // account creation via /authorize → /callback.
  res.redirect(`${AUTH_SERVER}/register?${params.toString()}`);
});

/**
 * GET /callback
 * The Auth Server redirects the browser here after authentication.
 *
 * Security checks performed:
 *   1. Presence of `code` and `state` parameters
 *   2. `state` matches the value stored in the session (CSRF mitigation)
 *   3. Auth code is exchanged server-to-server (client_secret never exposed)
 */
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Handle errors returned by the auth server
  if (error) {
    console.error(`Auth server error: ${error} — ${error_description}`);
    return res.redirect(`/?error=${encodeURIComponent(error_description || error)}`);
  }

  // Verify state to prevent CSRF attacks
  // The session must contain the state we generated in /login
  if (!state || !req.session.oauthState || state !== req.session.oauthState) {
    console.warn('[SECURITY] OAuth state mismatch — possible CSRF attempt');
    return res.redirect('/?error=invalid_state');
  }

  if (!code) {
    return res.redirect('/?error=missing_code');
  }

  // Clear the one-time state value immediately
  delete req.session.oauthState;

  try {
    // Exchange authorization code for access token (server-to-server)
    const tokenResponse = await fetch(`${AUTH_SERVER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type:    'authorization_code',
        code,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri:  REDIRECT_URI,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Token exchange failed:', tokenData);
      return res.redirect(`/?error=${encodeURIComponent(tokenData.error_description || 'token_exchange_failed')}`);
    }

    // Store the JWT in the server-side session.
    // The browser only receives a session cookie — the token is never exposed.
    req.session.accessToken     = tokenData.access_token;
    req.session.isAuthenticated = true;

    // Explicitly save before redirecting — without this, the browser can hit
    // /dashboard before the session write completes (saveUninitialized: false
    // does not guarantee a flush on redirect). Same pattern as auth server.
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
        return res.redirect('/?error=server_error');
      }
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('Callback error:', err.message);
    res.redirect('/?error=server_error');
  }
});

/**
 * GET /api/me
 * Returns the authenticated user's profile by proxying to the auth server's
 * /oauth/userinfo endpoint. The browser never sees the access token.
 */
app.get('/api/me', async (req, res) => {
  if (!req.session.isAuthenticated || !req.session.accessToken) {
    return res.status(401).json({ error: 'not_authenticated' });
  }

  try {
    const userRes = await fetch(`${AUTH_SERVER}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });

    if (!userRes.ok) {
      if (userRes.status === 401) {
        // Token expired or invalid — clear session and ask user to re-login
        req.session.destroy(() => {});
        return res.status(401).json({ error: 'session_expired' });
      }
      throw new Error(`Userinfo request failed: ${userRes.status}`);
    }

    const profile = await userRes.json();
    res.json(profile);
  } catch (err) {
    console.error('API /me error:', err.message);
    res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /dashboard
 * Protected page — redirects to home if not authenticated.
 */
app.get('/dashboard', (req, res) => {
  if (!req.session.isAuthenticated) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

/**
 * GET /logout
 * Destroys the server-side session and redirects to home.
 */
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);
    res.clearCookie('client.sid');
    // Use the configured REDIRECT_URI origin as the post-logout destination
    // so this works correctly in both local dev and production deployments.
    const appOrigin = new URL(REDIRECT_URI).origin;
    const postLogout = encodeURIComponent(`${appOrigin}/`);
    res.redirect(`${AUTH_SERVER}/logout?post_logout_redirect_uri=${postLogout}`);
  });
});

app.get('/api/search', async (req, res) => {
  const { q } = req.query;
  if (!req.session.isAuthenticated || !req.session.accessToken) {
    return res.status(401).json({ error: 'not_authenticated' });
  }

  try {
    const mutualFundResponse = await fetch(`http://api.mfapi.in/mf/search?q=$q`, {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });

    if (!mutualFundResponse.ok) {
      if (mutualFundResponse.status === 401) {
        // Token expired or invalid — clear session and ask user to re-login
        req.session.destroy(() => {});
        return res.status(401).json({ error: 'session_expired' });
      }
      throw new Error(`Userinfo request failed: ${userRes.status}`);
    }

    const mutualFundList = await mutualFundResponse.json();
    const results = mutualFundList.map(fund => fund.schemeName);
    console.log("Search results for query:", q, results);
    res.status(200).json({ results });
  } catch (err) {
    console.error('API /search error:', err.message);
    res.status(500).json({ error: 'server_error' });
  }
  
});
  // Simulate search results based on the query

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✓ Client app listening on http://localhost:${PORT}`);
  console.log(`  Auth Server: ${AUTH_SERVER}`);
  console.log(`  Environment: ${process.env.NODE_ENV || 'development'}`);
});
