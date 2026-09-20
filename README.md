# Auth Service

A standalone authentication and authorization microservice — the kind of shared internal
service other applications authenticate against, rather than a login form attached to one
frontend. API-only: Postman, curl, or Swagger UI is the interface.

**Status:** Milestones 1–2 of 8 complete — scaffold, plus email/password registration,
login with JWT issuing, and email verification. See [Roadmap](#roadmap).

---

## Stack

| Concern | Choice | Why |
| --- | --- | --- |
| Runtime | Node.js 22 + TypeScript | Strict mode, ESM |
| HTTP | Express 4 | Middleware model suits auth guards well |
| Database | PostgreSQL 16 + Prisma 7 | Typed queries, versioned migrations |
| Cache / counters | Redis 7 | Shared rate-limit state across instances |
| Password hashing | Argon2id | Memory-hard, so GPUs give an attacker little advantage |
| Tokens | JWT (HS256) | Stateless access tokens; no DB hit per request |
| Validation | Zod | One schema validates and types the request |
| Tests | Vitest + Supertest | Integration tests against the real app object |
| Logs | Pino | Structured JSON, secrets redacted at the logger |
| Packaging | Docker + Compose | `docker compose up` runs the whole stack |

---

## Architecture

Requests flow through a fixed pipeline. Each layer has one job, which keeps
authentication logic out of controllers and response formatting out of services.

```
                    ┌──────────────────────────────────────────┐
  HTTP request ───► │ helmet → cors → json → cookies → logger  │  cross-cutting
                    └──────────────────────────────────────────┘
                                      │
                    ┌──────────────────────────────────────────┐
                    │ rate limit → validate → authenticate →   │  per-route guards
                    │ authorize (RBAC)                         │  (milestones 2-6)
                    └──────────────────────────────────────────┘
                                      │
                    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                    │  routes/     │─►│ controllers/ │─►│  services/   │
                    │  (wiring)    │  │ (HTTP in/out)│  │ (logic)      │
                    └──────────────┘  └──────────────┘  └──────┬───────┘
                                                               │
                                              ┌────────────────┴────────────────┐
                                              ▼                                 ▼
                                    ┌──────────────────┐             ┌──────────────────┐
                                    │  PostgreSQL      │             │  Redis           │
                                    │  users, tokens,  │             │  rate limits,    │
                                    │  login attempts  │             │  ephemeral state │
                                    └──────────────────┘             └──────────────────┘
                                      │
                    ┌──────────────────────────────────────────┐
  HTTP response ◄── │ errorHandler → { error: { code, ... } }  │  single exit point
                    └──────────────────────────────────────────┘
```

### Current auth flow

```
REGISTER                                    LOGIN
────────                                    ─────
POST /auth/register                         POST /auth/login
  │                                           │
  ├─ validate (Zod)                           ├─ validate (Zod)
  ├─ email already known?                     ├─ look up user by email
  │    yes → email the owner a notice         ├─ no user / no password?
  │    no  → hash password (Argon2id)         │     └─ verify a throwaway hash
  │          INSERT user                      │        so timing matches, then 401
  │          store token HASH in Redis        ├─ verify password (Argon2id)
  │          email the raw token              │     mismatch → 401
  │                                           ├─ record LoginAttempt (either way)
  └─ 202, identical either way                └─ 200 + access token (15 min, HS256)

VERIFY                                      PROTECTED REQUEST
──────                                      ─────────────────
GET /auth/verify-email?token=…              GET /auth/me
  │                                           │  Authorization: Bearer <token>
  ├─ hash the token, GETDEL from Redis        ├─ authenticate: verify signature,
  │    (atomic → single use)                  │    expiry, issuer, audience, alg
  ├─ miss → 400                               │    → req.user = { id, role }
  └─ hit  → isEmailVerified = true            └─ controller loads and returns the user
```

Milestone 3 adds the refresh half: login also mints a rotating refresh token, stored
hashed, returned as an httpOnly cookie.

**Why this split:** controllers never touch the database, services never touch `req`/`res`.
That means business logic is unit-testable without faking an HTTP request, and every error
leaves through one handler that decides the status code and JSON shape — so no endpoint can
accidentally invent its own error format.

### Directory layout

```
src/
├── config/       env parsing (Zod-validated at startup), shared constants
├── routes/       route definitions — which middleware guards which endpoint
├── controllers/  request → response translation only
├── services/     business logic; no knowledge of HTTP
├── middleware/   error handler, async wrapper, validation, authenticate (RBAC to come)
├── lib/          Prisma + Redis clients, logger, AppError, password hashing, JWT, mailer
├── prisma/       schema.prisma + migrations
├── validators/   Zod request schemas
├── docs/         OpenAPI document
├── types/        Express request augmentation (req.user)
├── generated/    Prisma client output (gitignored — regenerated from the schema)
├── app.ts        builds the Express app (no listening — this is what tests import)
└── server.ts     connects dependencies, listens, handles graceful shutdown
```

---

## Getting started

### Option A — everything in Docker

```bash
cp .env.example .env

# Generate the two JWT secrets (they must differ from each other)
echo "JWT_ACCESS_SECRET=$(openssl rand -base64 48)"   # paste into .env
echo "JWT_REFRESH_SECRET=$(openssl rand -base64 48)"  # paste into .env

docker compose up --build
```

This starts Postgres, Redis, and the API, applies pending migrations, and serves on
<http://localhost:3000>.

```bash
curl http://localhost:3000/api/v1/health/ready
# {"status":"ok","uptimeSeconds":3,"dependencies":{"database":"up","redis":"up"}}
```

### Option B — datastores in Docker, app on the host (for development)

```bash
cp .env.example .env            # then fill in the two JWT secrets as above
docker compose up -d postgres redis
npm install
npm run prisma:generate         # generates the typed client from schema.prisma
npm run prisma:migrate          # applies migrations to the local database
npm run dev                     # tsx watch — restarts on file change
```

> **Ports:** Postgres is published on host port **5433** and Redis on **6380**, not their
> defaults, so this stack can run at the same time as another local Postgres/Redis. Inside
> the Compose network the services still use 5432/6379. Override with `POSTGRES_PORT` /
> `REDIS_PORT` in `.env`.

### Scripts

| Command | Does |
| --- | --- |
| `npm run dev` | Watch-mode dev server |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Run the compiled server |
| `npm run typecheck` | Type-check without emitting |
| `npm test` | Run the test suite once |
| `npm run test:watch` | Tests in watch mode |
| `npm run prisma:generate` | Regenerate the Prisma client after editing the schema |
| `npm run prisma:migrate` | Create + apply a migration (development) |
| `npm run prisma:deploy` | Apply existing migrations (production) |
| `npm run prisma:studio` | Browse the database in a GUI |

---

## Endpoints

Everything is mounted under `/api/v1` so a future breaking change can ship as `/api/v2`
alongside it, instead of forcing every consumer to redeploy on the same day.

The machine-readable contract is served at `GET /api/v1/openapi.json` — import it into
Postman or Insomnia. Swagger UI is mounted on top of it in milestone 7.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/health/live` | — | Liveness. Touches no dependencies: a database outage should not cause an orchestrator to restart a healthy process. |
| `GET` | `/api/v1/health/ready` | — | Readiness. Pings Postgres and Redis; returns `503` if either is down, so a load balancer stops routing here. |
| `POST` | `/api/v1/auth/register` | — | Create an account. Always `202`, whether or not the email was taken (see below). |
| `POST` | `/api/v1/auth/login` | — | Exchange credentials for an access token. |
| `GET` | `/api/v1/auth/verify-email` | — | Confirm an address using the token from the emailed link. Single-use. |
| `POST` | `/api/v1/auth/resend-verification` | — | Request a fresh verification link. |
| `GET` | `/api/v1/auth/me` | Bearer | The authenticated user. |
| `GET` | `/api/v1/openapi.json` | — | OpenAPI 3.1 description of everything above. |

### Walking the full flow

```bash
# 1. Register. Response is identical whether or not the email already exists.
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"correct-horse-battery-staple"}'
# => 202 {"message":"If that email address is available, a verification link has been sent to it."}

# 2. The mailer is stubbed, so the verification link is logged instead of sent.
#    Grab it from the server output:
#    "[stub mailer] email would be sent" ... /api/v1/auth/verify-email?token=<TOKEN>

# 3. Verify. Using the same link twice fails — the token is consumed atomically.
curl "http://localhost:3000/api/v1/auth/verify-email?token=<TOKEN>"
# => 200 {"message":"Email address verified. You can now sign in."}

# 4. Log in.
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"correct-horse-battery-staple"}'
# => 200 {"user":{...},"accessToken":"eyJhbGciOi...","tokenType":"Bearer","expiresIn":900}

# 5. Call a protected endpoint.
curl http://localhost:3000/api/v1/auth/me -H "Authorization: Bearer <ACCESS_TOKEN>"
# => 200 {"user":{"id":"...","email":"dev@example.com","role":"USER","isEmailVerified":true,...}}
```

### Two deliberate deviations from the conventional REST answer

**Registration never says "that email is taken."** A `409 Conflict` is the usual reply, and
it is also a user-enumeration oracle: feed it a list of addresses and it tells you which
ones have accounts here — useful for phishing and credential stuffing. So both branches
return the same `202` and the same body. When the address is already registered, a notice
goes to the address's real owner instead ("someone tried to create an account with your
email"), which reaches the person who needs to know and tells an attacker nothing.

The cost is honest: a client cannot show "email already taken" at signup, and the user
finds out by email. That trade-off is taken on purpose, and the same reasoning drives the
single generic failure on login.

**An unknown email and a wrong password are indistinguishable on login** — same `401`,
same body, and comparable timing. The timing part needs explicit work: verifying a real
password costs ~50 ms of Argon2, while bailing out early on an unknown email costs
microseconds. That gap alone leaks which addresses exist, so the unknown-email path
verifies against a throwaway hash to spend the same time
([`src/lib/password.ts`](src/lib/password.ts)).

### Error format

Every failure — validation, auth, 404, unexpected crash — returns the same shape:

```json
{ "error": { "code": "NOT_FOUND", "message": "Route GET /api/v1/nope not found" } }
```

Clients switch on `code`, never on `message`. Codes are part of the API contract
(`VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`,
`INTERNAL_ERROR`); messages can be reworded freely. Validation failures add a `details`
array naming each bad field. Stack traces are never returned in production — they leak
table names and file paths that help an attacker map the system.

---

## Data model

Defined in [`src/prisma/schema.prisma`](src/prisma/schema.prisma).

```
User ──┬── OAuthAccount   (provider + providerUserId, unique per provider)
       ├── RefreshToken   (hash only, rotation chain via replacedBy)
       └── LoginAttempt   (durable audit trail of every attempt)
```

Three decisions worth calling out, since they are the parts an interviewer tends to probe:

- **`User.passwordHash` is nullable.** An account created through Google has no password.
  Making the column required would mean inventing a fake password for OAuth users, which is
  worse than modelling "this user has no password" honestly.
- **Refresh tokens are stored as hashes, never raw.** If the database leaks, the stored
  hashes cannot be replayed against the API — the same reasoning as password hashing. The
  raw token exists only in the client's httpOnly cookie.
- **Spent refresh tokens are kept, not deleted.** Rotation marks the old row revoked and
  points `replacedBy` at its successor. Because the row survives, a *second* use of an
  already-rotated token is detectable — the signal that a token was stolen, which lets the
  whole chain be revoked rather than trusting the thief.

---

## Security posture (so far)

| Measure | Where |
| --- | --- |
| Passwords hashed with Argon2id (19 MiB, t=2), unique salt per hash | [`src/lib/password.ts`](src/lib/password.ts) |
| Registration and login reveal nothing about which emails exist | [`src/services/auth.service.ts`](src/services/auth.service.ts) |
| Constant-ish login timing for unknown accounts | [`src/lib/password.ts`](src/lib/password.ts) |
| JWT algorithm pinned to HS256, issuer + audience verified | [`src/lib/jwt.ts`](src/lib/jwt.ts) |
| Access tokens carry `type: "access"`, so a refresh token cannot be replayed as one | [`src/lib/jwt.ts`](src/lib/jwt.ts) |
| Verification tokens stored hashed, single-use via atomic `GETDEL` | [`src/services/verification.service.ts`](src/services/verification.service.ts) |
| Unknown request fields stripped before reaching Prisma (no `role` injection) | [`src/middleware/validate.ts`](src/middleware/validate.ts) |
| Every login attempt recorded for the audit trail | [`src/services/auth.service.ts`](src/services/auth.service.ts) |
| Email links built from configured `APP_BASE_URL`, never the `Host` header | [`src/config/env.ts`](src/config/env.ts) |
| Security headers (HSTS, nosniff, frame denial, CSP) | `helmet()` in [`src/app.ts`](src/app.ts) |
| CORS allowlist, no wildcard with credentials | [`src/app.ts`](src/app.ts) |
| Request body size cap (100 kb) | [`src/app.ts`](src/app.ts) |
| Framework fingerprint removed | `x-powered-by` disabled |
| Config validated at boot, process exits if invalid | [`src/config/env.ts`](src/config/env.ts) |
| Separate secrets for access vs refresh tokens | `.env.example` |
| Secrets redacted from logs at the logger, not per call site | [`src/lib/logger.ts`](src/lib/logger.ts) |
| Internal error details hidden in production | [`src/middleware/error-handler.ts`](src/middleware/error-handler.ts) |
| Container runs as non-root | [`Dockerfile`](Dockerfile) |
| Graceful shutdown drains in-flight requests | [`src/server.ts`](src/server.ts) |

---

## Testing

```bash
docker compose up -d postgres redis   # the suite needs real datastores
npm test                              # 51 tests
```

Tests run against a real Postgres, not a mocked Prisma client, because the behaviour most
worth testing is exactly what a mock would fake away: the unique constraint on email,
cascade deletes, how a duplicate key actually surfaces. Global setup creates and migrates
an `auth_test` database automatically, so a fresh clone needs no manual `psql` step.

Integration tests import the Express app directly rather than starting a server, so
Supertest binds an ephemeral port per request — no port collisions, no server cleanup.
Files run in a single worker because they share one Postgres and one Redis; parallel files
would race each other's data.

The suite targets failure paths, not just happy ones. Currently covered:

- Registration: duplicate email indistinguishable from a fresh one, email case folding,
  password never stored or returned in plaintext, a client-supplied `role` field ignored
- Login: wrong password, unknown email (byte-identical response), OAuth-only account with
  a null `passwordHash`, audit rows written for both success and failure
- Tokens: expired, wrong secret, wrong audience, `"alg": "none"` forgery, malformed header,
  non-Bearer scheme, and a valid token whose user has since been deleted
- Verification: replaying a used link, unknown token, and confirmation that only the
  token's hash is ever stored

Expired refresh tokens, reuse detection and rate-limit tripping join the list as those
milestones land.

---

## Roadmap

- [x] **1. Scaffold** — Express + TypeScript + Prisma + Redis + Docker Compose, health checks, error handling
- [x] **2. Email/password auth** — register, login, JWT issuing, email verification (stubbed mailer)
- [ ] **3. Refresh token rotation** — reuse detection, logout, revocation
- [ ] **4. RBAC** — role middleware, protected example routes
- [ ] **5. OAuth2** — Google + GitHub, account linking
- [ ] **6. Rate limiting** — per-IP and per-account, brute-force protection
- [ ] **7. Docs** — OpenAPI spec + auth flow diagram
- [ ] **8. Stretch** — TOTP-based 2FA

---

## Notes

- `npm audit` reports advisories in `mysql2`, a transitive dependency of the Prisma CLI.
  This service uses PostgreSQL, so that driver is never loaded at runtime.
- The `prisma` CLI is pinned to 7.10.0 rather than `latest`, because npm's `latest` tag for
  it currently points at an 8.0.0 release candidate that does not match `@prisma/client`.
