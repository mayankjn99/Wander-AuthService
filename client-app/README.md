# Client App

A minimal OAuth 2.0 **confidential client** that authenticates users via the centralized Auth Server.

Implements the **Backend-for-Frontend (BFF)** pattern: the `client_secret` and access token are kept server-side; the browser only receives a session cookie.

---

## Tech Stack

| Concern | Library |
|---|---|
| Web framework | Express.js |
| Session management | express-session |
| HTTP client | Node.js built-in `fetch` (≥ v18) |
| UI | Vanilla HTML + CSS |

---

## Local Setup

### Prerequisites
- Node.js ≥ 18
- Auth Server running on `http://localhost:3000`

### 1. Install dependencies

```bash
cd client-app
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
AUTH_SERVER_URL=http://localhost:3000

# Must match CLIENT_ID / CLIENT_SECRET in auth-server .env
CLIENT_ID=client-app-1
CLIENT_SECRET=<same value as auth-server CLIENT_SECRET>

REDIRECT_URI=http://localhost:3001/callback

SESSION_SECRET=<64-char random hex string>

PORT=3001
NODE_ENV=development
```

### 3. Start

```bash
npm run dev   # development
npm start     # production
```

App runs on **http://localhost:3001**.

---

## Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Landing page with "Sign In" button |
| `GET` | `/login` | Generates `state`, redirects to Auth Server `/authorize` |
| `GET` | `/callback` | Handles return from Auth Server; exchanges code for token |
| `GET` | `/dashboard` | Protected page (requires session) |
| `GET` | `/api/me` | Returns user profile JSON (proxied from Auth Server) |
| `GET` | `/logout` | Destroys session |

---

## Authentication Flow

```
Browser                  Client App (port 3001)          Auth Server (port 3000)
   │                            │                                │
   │── GET /login ─────────────>│                                │
   │                            │ generate state, save to session│
   │<── 302 /authorize?... ─────│────────────────────────────────>
   │──────────────────────────────────────────────────────────────>
   │                            │            render login form   │
   │<─────────────────────────────────────────────────────────────
   │ POST /login (credentials)  │                                │
   │──────────────────────────────────────────────────────────────>
   │<── 302 /callback?code=X&state=Y ─────────────────────────────
   │── GET /callback?code=X&state=Y ──>│                          │
   │                            │ verify state == session.state  │
   │                            │── POST /oauth/token ──────────>│
   │                            │<── { access_token: JWT } ──────│
   │                            │ store token in session         │
   │<── 302 /dashboard ─────────│                                │
   │── GET /dashboard ─────────>│                                │
   │<── dashboard.html ─────────│                                │
   │── GET /api/me ────────────>│                                │
   │                            │── GET /oauth/userinfo ─────────>
   │                            │<── { email, username, ... } ───│
   │<── { email, username } ────│                                │
```

---

## Security Notes

- **`client_secret` is never exposed to the browser.** All token exchange happens server-to-server in `/callback`.
- **CSRF protection via `state`** — a 16-byte hex random string generated per login, stored in the server-side session, and verified on return.
- **Access token stored in session** — the JWT lives in `req.session.accessToken`, not in a cookie or `localStorage` accessible to browser JS.
- **Session cookie** — `httpOnly`, `secure` (production), `sameSite: lax`.
- **Token expiry** — if the Auth Server's `/oauth/userinfo` returns 401, the client clears the session and redirects to `/`.
