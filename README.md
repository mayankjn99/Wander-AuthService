# Centralized Redirect Authentication System

A production-pattern **OAuth 2.0 Authorization Code** implementation consisting of two independent services:

| Service | Port | Responsibilities |
|---|---|---|
| **Auth Server** | 3000 | Renders Login/Register UI; issues JWTs; manages sessions |
| **Client App** | 3001 | Consumes Auth Server via redirect; renders protected content |

---

## Quick Start

### 1. Start MongoDB locally

```bash
# macOS (Homebrew)
brew services start mongodb-community

# Or via Docker
docker run -d -p 27017:27017 --name mongo mongo:7
```

### 2. Auth Server

```bash
cd auth-server
npm install
cp .env.example .env        # fill in secrets (see auth-server/README.md)
npm run dev
```

### 3. Client App (in a new terminal)

```bash
cd client-app
npm install
cp .env.example .env        # fill in CLIENT_SECRET to match auth-server .env
npm run dev
```

### 4. Open the app

Visit **http://localhost:3001** and click **Sign In**.

---

## Repository Layout

```
authService/
├── auth-server/
│   ├── controllers/
│   │   └── authController.js   # OAuth logic, bcrypt, JWT signing
│   ├── models/
│   │   └── User.js             # Mongoose schema
│   ├── routes/
│   │   └── authRoutes.js       # Express routes + express-validator chains
│   ├── views/
│   │   ├── login.ejs           # Server-rendered login form (Tailwind)
│   │   └── register.ejs        # Server-rendered registration form (Tailwind)
│   ├── server.js               # App entry point (Helmet, rate limit, session)
│   ├── .env.example
│   └── README.md
│
├── client-app/
│   ├── public/
│   │   ├── index.html          # Landing page ("Sign In" button)
│   │   ├── dashboard.html      # Protected dashboard
│   │   └── style.css
│   ├── server.js               # BFF: state generation, code exchange, /api/me
│   ├── .env.example
│   └── README.md
│
└── README.md                   # ← You are here
```

---

## Security Architecture

### Password Security
Passwords are hashed with **bcrypt at 12 rounds** before being stored in MongoDB. The `password` field has a `minlength: 60` constraint enforcing only bcrypt hashes can persist. Plaintext passwords are never logged or serialized.

### XSS Prevention
- All user inputs on `/login` and `/register` are validated and sanitized by `express-validator` before any processing.
- EJS templates use `<%= %>` (auto-escaped) exclusively for user-supplied values — `<%- %>` (raw output) is never used for user data.
- `helmet` sets `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and other protective headers.

### CSRF Mitigation (OAuth State)
The Client App generates a 16-byte cryptographically random `state` value using `crypto.randomBytes(16).toString('hex')` and stores it in the server-side session before redirecting to `/authorize`. On return, the `state` in the URL is compared to the session value. A mismatch causes an immediate rejection — no token is requested.

### Cookie Security
Both the Auth Server and Client App session cookies are configured with:
```js
{
  httpOnly: true,                                    // inaccessible to browser JS
  secure: process.env.NODE_ENV === 'production',     // HTTPS only in production
  sameSite: 'lax',                                   // sent on top-level navigations only
}
```

### Rate Limiting & Headers
- `express-rate-limit`: 30 requests per 15-minute window per IP on all auth endpoints.
- `helmet`: sets 11+ security-relevant HTTP headers automatically.

---

## Debugging & Troubleshooting

### 1. "Invalid State Parameter" Errors

**What it means:** The `state` returned by the auth server does not match the value stored in the client app's session.

**How the state mechanism works:**
1. Client app generates `state = crypto.randomBytes(16).toString('hex')`.
2. `state` is stored in `req.session.oauthState` (server-side session).
3. `state` is sent to the auth server as a query parameter.
4. Auth server echoes the same `state` back in the redirect.
5. Client app checks `req.query.state === req.session.oauthState`.

**Common causes and fixes:**

| Symptom | Cause | Fix |
|---|---|---|
| Error on first login | Session cookie not set before redirect | Check `SESSION_SECRET` is set; ensure session middleware is registered before routes |
| Error after working previously | Browser blocked third-party cookies | Test in incognito; check `SameSite` setting |
| Error intermittently | Multiple tabs or back-button usage | Each `/login` click creates a new state; back-button re-submits a stale state |
| Error in production | `secure: true` cookie not sent over HTTP | Ensure the client app is served over HTTPS in production |

**Debug steps:**
```bash
# 1. Add temporary logging in client-app/server.js /callback:
console.log('session state:', req.session.oauthState);
console.log('url state:    ', req.query.state);

# 2. Check that the session cookie is being set by inspecting
#    browser DevTools → Application → Cookies → localhost:3001
```

---

### 2. CORS Failures on Token Exchange

**Key distinction:**
- The `/authorize` redirect is a **browser navigation** — no CORS headers are needed.
- The `/oauth/token` POST is a **server-to-server fetch** from the client app's Express process — CORS applies only if called directly from a browser (which it shouldn't be in the BFF pattern).

**If you see CORS errors on `/oauth/token`:**

1. Check that you're calling `/oauth/token` from the client app **server** (not browser JS).
2. If you need browser-side token exchange (not recommended), add the caller's origin to `ALLOWED_ORIGINS` in the auth server `.env`:

```env
ALLOWED_ORIGINS=http://localhost:3001,https://your-app.vercel.app
```

3. Verify the auth server is actually running — a connection refused error can masquerade as a CORS error in some browsers.

4. The auth server applies CORS only to `/oauth/*` routes. The `/authorize`, `/login`, and `/register` routes are browser-redirect based and do not need CORS headers.

---

### 3. Cookies Not Setting in Browser

**Local development (HTTP):**
- Both apps run on `localhost`, which the browser treats as secure for `SameSite` purposes.
- `secure: false` (the default when `NODE_ENV !== 'production'`) allows cookies over HTTP.
- If cookies still don't appear: open DevTools → Network → inspect the Set-Cookie response header. A missing header indicates the session middleware is not running.

**Production (HTTPS, separate domains):**

| Scenario | Problem | Fix |
|---|---|---|
| Auth server on `auth.example.com`, client on `app.example.com` | Browsers block cross-site cookies in some contexts | Use `sameSite: 'none'` + `secure: true` on the auth server cookie (required for cross-site iframes) — not needed for redirects |
| Deployed to Render/Vercel but using HTTP | `secure: true` cookies are rejected over HTTP | Ensure your hosting provider enforces HTTPS (Render and Vercel do this automatically) |
| Cookie set but missing on redirect | `SameSite: lax` blocks cookies on cross-site POST | The redirect from auth server to client is a GET, so `lax` is fine for top-level navigations |

**Debug commands:**
```bash
# Check response headers locally
curl -v -c /tmp/cookies.txt http://localhost:3001/login 2>&1 | grep -i 'set-cookie'
```

---

### 4. Invalid Redirect URI Errors

The auth server validates `redirect_uri` against the `ALLOWED_REDIRECT_URIS` environment variable **before issuing any authorization code**. This is a critical security control that prevents [Open Redirect attacks](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), where an attacker could substitute a malicious callback URL to steal the authorization code.

**Symptoms:**
```json
{ "error": "invalid_redirect_uri", "error_description": "The redirect_uri is not registered..." }
```

**Fixes:**

1. Ensure `REDIRECT_URI` in `client-app/.env` exactly matches one of the values in `ALLOWED_REDIRECT_URIS` in `auth-server/.env` — including protocol, port, and path.

```env
# auth-server .env
ALLOWED_REDIRECT_URIS=http://localhost:3001/callback,https://myapp.vercel.app/callback

# client-app .env
REDIRECT_URI=http://localhost:3001/callback
```

2. Trailing slashes matter: `http://localhost:3001/callback` ≠ `http://localhost:3001/callback/`.

3. After updating `.env`, **restart both servers** — the allowlist is read at startup.

4. **Never use a wildcard allowlist** like `http://localhost:*`. Always specify exact URIs.

---

## Deployment

### Database — MongoDB Atlas

1. Create a free account at [mongodb.com/atlas](https://www.mongodb.com/atlas).
2. Create a free **M0** cluster (choose a region close to your servers).
3. Under **Database Access** → Add a new user with a strong password.
4. Under **Network Access** → Add IP Address → Allow access from anywhere: `0.0.0.0/0`.  
   (For serverless/PaaS deployments where the outbound IP changes dynamically.)
5. Under **Deployment → Database** → Connect → Drivers → copy the connection string:
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/auth-server?retryWrites=true&w=majority
   ```
6. Set this as `MONGO_URI` in the auth server's environment variables.

---

### Auth Server — Render

1. Push `auth-server/` to a GitHub repository.
2. Go to [render.com](https://render.com) → New → Web Service.
3. Connect your GitHub repo.
4. Configure:
   - **Root Directory:** `auth-server`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Environment:** Node
5. Add environment variables:

   | Key | Value |
   |---|---|
   | `MONGO_URI` | Your Atlas connection string |
   | `JWT_SECRET` | 64-char random hex |
   | `SESSION_SECRET` | 64-char random hex |
   | `CLIENT_ID` | `client-app-1` |
   | `CLIENT_SECRET` | Your shared secret |
   | `ALLOWED_REDIRECT_URIS` | `https://your-client-app.vercel.app/callback` |
   | `ALLOWED_ORIGINS` | `https://your-client-app.vercel.app` |
   | `NODE_ENV` | `production` |

6. Deploy. Note the assigned URL (e.g. `https://auth-server-xxxx.onrender.com`).

> **Railway alternative:** Same steps — connect repo, set environment variables, Railway auto-detects Node.js.

---

### Client App — Vercel

1. Push `client-app/` to a GitHub repository.
2. Go to [vercel.com](https://vercel.com) → New Project → Import your repo.
3. Configure:
   - **Root Directory:** `client-app`
   - **Framework Preset:** Other
   - **Build Command:** *(leave blank — no build step needed)*
   - **Output Directory:** *(leave blank)*
   - **Install Command:** `npm install`
   - **Override Start Command:** `node server.js`

   > **Note:** Vercel is optimized for static/serverless deployments. For a persistent Express server with sessions, **Render** or **Railway** is a better fit for the client app too.

4. Add environment variables:

   | Key | Value |
   |---|---|
   | `AUTH_SERVER_URL` | `https://auth-server-xxxx.onrender.com` |
   | `CLIENT_ID` | `client-app-1` |
   | `CLIENT_SECRET` | Your shared secret |
   | `REDIRECT_URI` | `https://your-client-app.onrender.com/callback` |
   | `SESSION_SECRET` | 64-char random hex |
   | `NODE_ENV` | `production` |

5. Deploy.

**SPA routing note:** If migrating the client app to a React SPA (Vite), configure a fallback in `vercel.json` so all routes resolve to `index.html`:

```json
{
  "rewrites": [{ "source": "/((?!api/).*)", "destination": "/index.html" }]
}
```

---

### Post-Deployment Checklist

- [ ] Both apps are served over HTTPS.
- [ ] `NODE_ENV=production` is set on both apps.
- [ ] `ALLOWED_REDIRECT_URIS` on the auth server matches the deployed client app's `/callback` URL.
- [ ] `ALLOWED_ORIGINS` on the auth server matches the deployed client app's origin.
- [ ] MongoDB Atlas network access is configured.
- [ ] Session cookies appear in browser DevTools after login.
- [ ] `/oauth/userinfo` returns a valid profile when called with a fresh token.

---

## Generating Secrets

```bash
# Run once per secret — use different values for JWT_SECRET and SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## License

MIT
