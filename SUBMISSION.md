# WanderOn Auth Service — Submission Report

**Live App:** https://wander-client-app.onrender.com
**GitHub:** https://github.com/mayankjn99/Wander-AuthService
**Stack:** Node.js 20 · Express 4 · MongoDB Atlas · JWT (HS256) · OAuth 2.0

---

## What Was Built

A production-deployed, two-service authentication system implementing the **OAuth 2.0 Authorization Code Grant** flow. The system is split into two independent services that communicate over HTTPS:

| Service | URL | Role |
|---------|-----|------|
| **Auth Server** | `wander-auth-service.onrender.com` | Identity Provider — owns credentials, sessions, token issuance |
| **Client App** | `wander-client-app.onrender.com` | Backend-for-Frontend — confidential OAuth client |
| **Database** | MongoDB Atlas (M0) | Managed cloud database — user storage |

---

## Functionality

### Registration
- User submits username, email, password, confirm password
- Server validates all fields (format, length, uniqueness)
- Password hashed with **bcrypt (12 rounds)** before storage
- Session created, user redirected to dashboard

### Login
- Accepts **email or username** — user can sign in with either
- Credentials verified via `bcrypt.compare`
- Session regenerated on success (session fixation prevention)
- Redirects through OAuth flow to dashboard

### JWT Generation
- Auth server issues a signed **HS256 JWT** on successful code exchange
- Claims: `sub` (userId), `email`, `username`, `aud` (client\_id), `iss` (auth-server)
- Expiry: **1 hour**
- Token stored **server-side only** — never sent to the browser

### Dashboard
- Client app proxies `/api/me` → Auth Server `/oauth/userinfo`
- Returns user profile (username, email, member since)
- Browser only ever sees a session cookie — never the raw JWT

---

## OAuth 2.0 Flow

```
Browser → Client App → Auth Server → MongoDB
   │                                        
   1. GET /login (client generates state, redirects to /authorize)
   2. Auth Server validates client, redirects to /login form
   3. User submits credentials → bcrypt verify → session saved
   4. /authorize issues single-use auth code (256-bit entropy)
   5. Browser redirected to /callback?code=X&state=Y
   6. Client App verifies state (CSRF check)
   7. Client App exchanges code → JWT (server-to-server, secret never exposed)
   8. JWT stored in server session, browser redirected to /dashboard
   9. Dashboard fetches /api/me → proxied to /oauth/userinfo
```

---

## Code Quality

### Structure
```
authService/
├── auth-server/          # Identity Provider (Express)
│   ├── app.js            # Middleware stack (single responsibility)
│   ├── server.js         # Entry point — env validation + DB boot
│   ├── controllers/      # Business logic (one controller, clear sections)
│   ├── models/           # Mongoose schema
│   ├── routes/           # Route table + validation chains
│   ├── views/            # EJS templates (login, register)
│   └── public/js/        # CSP-safe client-side validation
└── client-app/           # BFF (Express)
    ├── server.js          # All routes in one file (appropriately small)
    └── public/            # Static HTML/CSS (index, dashboard)
```

### Principles Applied

**Single Responsibility** — `app.js` only configures middleware; `server.js` only boots the process; `authController.js` owns all OAuth logic; `authRoutes.js` owns only routing and input validation.

**DRY** — `oauthQueryString()` helper reused across all render calls; `wireField()` in validation.js registers any field with one call; `mustBeString()` guard applied once and reused across all validators.

**Separation of Concerns** — validation at three independent layers (client JS → express-validator → Mongoose schema) so no single layer is a single point of failure.

**No over-engineering** — no unnecessary abstractions. The auth code store is an in-memory `Map` (appropriate for single-instance free tier). No framework beyond Express.

---

## Security

| Threat | Mitigation |
|--------|-----------|
| Plaintext passwords | bcrypt 12 rounds; Mongoose `minlength: 60` rejects anything that isn't a hash |
| Password enumeration | Constant-time 300ms delay on unknown email/username |
| Session fixation | `req.session.regenerate()` on every login and registration |
| Session race condition | Explicit `req.session.save()` before every redirect after mutation |
| CSRF on OAuth callback | 16-byte cryptographic `state` per flow, verified server-side |
| Open Redirect | `redirect_uri` validated against a strict per-client allowlist |
| Auth code replay | Single-use flag + immediate deletion after exchange |
| Client impersonation | `crypto.timingSafeEqual` for `client_secret` comparison |
| JWT scope creep | `audience` claim bound to `client_id` at issuance |
| XSS | CSP `script-src 'self'`; all user data written via `textContent`, never `innerHTML`; EJS auto-escaping |
| NoSQL injection | `mustBeString()` guard rejects any non-string value before it reaches a MongoDB query |
| DoS via large payloads | Body size limited to 10kb on all parsers |
| Brute force | Rate limiting: 300 requests / 15 min per IP |
| Cookie theft | `httpOnly: true`, `secure: true` (production), `sameSite: lax` |
| Cookie collision | Distinct cookie names: `auth.sid` vs `client.sid` |
| JWT exposure | Token stored in server-side session only — never in browser storage or response body |
| Reverse proxy bypass | `app.set('trust proxy', 1)` ensures secure cookies work behind Render's load balancer |

---

## Architecture Design

### Why Two Services?

The Authorization Code flow **requires** a `client_secret` to exchange an auth code for a token. That secret must never reach the browser. The Client App acts as a Backend-for-Frontend (BFF) — it holds the secret and the JWT server-side, sharing only an opaque session cookie with the browser.

### Why In-Memory Session Store?

On the free Render tier (single instance), `express-session`'s default memory store is appropriate. For multi-instance production, this would be replaced with Redis (a one-line change to the session config).

### Why MongoDB Atlas?

Managed database removes infrastructure concern. Schema-level constraints (`unique`, `minlength`, regex `match`) provide a physical last line of defence independent of application code.

### Scalability Path

| Component | Current | Production upgrade |
|-----------|---------|-------------------|
| Session store | In-memory | Redis (connect-redis) |
| Auth codes | In-memory Map | Redis with TTL |
| Database | Atlas M0 (free) | Atlas M10+ with replica set |
| Services | Single instance | Horizontal scale (stateless once Redis added) |

---

## Error Handling

| Scenario | Handling |
|----------|---------|
| Invalid field format | express-validator returns field-specific error; EJS pre-applies `field-error` CSS class server-side |
| Unknown email/username | 200 with "No account found" + register hint link; 300ms delay prevents enumeration |
| Wrong password | 200 with "Incorrect password" on password field only |
| Duplicate email/username on register | Checked with `findOne` + MongoDB `err.code === 11000` fallback for race conditions |
| Expired auth code | Deleted from store, `invalid_grant` returned |
| Reused auth code | Immediate deletion + security warning logged |
| JWT expired | `/oauth/userinfo` returns `401`; client app destroys session, redirects to login |
| Session save failure | Caught in callback, renders error page — never swallowed silently |
| Missing env vars | `server.js` validates all required vars at startup and calls `process.exit(1)` with a clear message |
| Reverse proxy errors | `trust proxy` configured; logout redirect derived from `REDIRECT_URI` env var |

Client-side validation provides immediate feedback on blur (field glow, error message, password strength meter) before the form can even be submitted.

---

## Documentation

| Artifact | Location |
|----------|---------|
| Architecture report + sequence diagrams | `ARCHITECTURE.md` |
| `.env.example` with all variables explained | `auth-server/.env.example`, `client-app/.env.example` |
| Inline comments on every non-obvious decision | Throughout codebase |
| Test descriptions as living documentation | `auth-server/tests/*.test.js` (42 tests) |

---

## Test Coverage — 42 Tests

```
auth-server/tests/
├── login.test.js          14 tests — email login, username login, OAuth flow,
│                                     session persistence, error isolation
├── registration.test.js   11 tests — user creation, bcrypt storage, duplicate
│                                     detection, session save, redirect chain
└── oauth.test.js          17 tests — authorize, token exchange, code replay,
                                      userinfo, full end-to-end flow
```

Run locally:
```bash
cd auth-server && npm test
```

---

## Deployment

| Component | Platform | URL |
|-----------|----------|-----|
| Client App | Render (free) | https://wander-client-app.onrender.com |
| Auth Server | Render (free) | https://wander-auth-service.onrender.com |
| Database | MongoDB Atlas M0 | `wander-cluster.odoubio.mongodb.net` |

Both services deploy automatically on push to `main`. Node.js pinned to `20.11.1` via `.node-version`. Public npm registry enforced via `.npmrc` to avoid corporate Artifactory resolution on Render's build servers.
