# Auth Service

A standalone authentication and authorization microservice — the kind of shared internal
service other applications authenticate against, rather than a login form attached to one
frontend. API-only: Postman, curl, or Swagger UI is the interface.

**Status:** Milestones 1–6 of 8 complete — scaffold, email/password auth with JWT issuing,
rotating refresh tokens with reuse detection, permission-based access control, and
Google/GitHub sign-in with account linking, and Redis-backed rate limiting with
brute-force protection. See [Roadmap](#roadmap).

---

## Stack

| Concern | Choice | Why |
| --- | --- | --- |
| Runtime | Node.js 22 + TypeScript | Strict mode, ESM |
| HTTP | Express 4 | Middleware model suits auth guards well |
| Database | PostgreSQL 16 + Prisma 7 | Typed queries, versioned migrations |
| Cache / counters | Redis 7 | Shared rate-limit state across instances |
| Password hashing | Argon2id | Memory-hard, so GPUs give an attacker little advantage |
| Tokens | JWT (HS256) access + opaque refresh | Stateless auth per request, with real revocation |
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

### Token lifecycle

Two token types, because one cannot be both cheap to check and possible to revoke:

|  | Access token | Refresh token |
| --- | --- | --- |
| Form | Signed JWT (HS256) | Opaque 256-bit random string |
| Lifetime | 15 minutes | 7 days |
| Checked by | Signature only — no DB hit | Database lookup every time |
| Carried in | `Authorization: Bearer` header | httpOnly cookie |
| Stored server-side | Not at all | SHA-256 hash only |
| Revocable | ✗ — valid until it expires | ✓ — instantly |

The access token is fast because nothing is consulted to validate it, which is exactly why
it cannot be revoked; the 15-minute TTL is what bounds that exposure. The refresh token is
the opposite bargain: a database round trip per use, in exchange for instant revocation.

```
login ──► RT₁ ─────────────────────────────────► rotate ──► RT₂ ──► rotate ──► RT₃
             │                                                 │
             │ revokedAt set, replacedBy → RT₂                 │ …and so on
             │ (row kept, never deleted)                       │
             │
             └─ someone presents RT₁ a SECOND time
                        │
                        ▼
                REUSE DETECTED → revoke every session for that user
```

**Why rotation exists.** A refresh token is a bearer credential: nothing about it
distinguishes the real user from someone who copied it. But only one party can spend it
*first*. The loser presents an already-spent token, and that second use is the alarm.
Without rotation a stolen token simply works, quietly, for its full seven days, and the
theft is never observable at all.

**Why the spent row is kept.** Deleting it would make a replayed token indistinguishable
from a random string — "unknown token", not "this was stolen". `replacedBy` is what turns
that into evidence.

**Why reuse revokes everything.** At the moment of detection we cannot tell which of the
two parties is legitimate, so we trust neither. With the v1 schema there is no `familyId`
tying one rotation chain together, so "all sessions for this user" is a deliberate
over-approximation: it signs the real user out of their other devices too. When a
credential is known to have leaked, cutting too much is cheaper than leaving an attacker a
working session — and a `familyId` column would narrow it later.

One subtlety worth the code it costs: a token revoked *by rotation* (`replacedBy` set) is
theft evidence, while one revoked by logout or by an earlier cascade is not. Treating both
as reuse would mean that after a single incident, every other device raises its own "reuse
detected" alarm on its next refresh — turning one real signal into a flood
([`refresh-token.service.ts`](src/services/refresh-token.service.ts)).

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
├── lib/          Prisma + Redis clients, logger, AppError, password hashing, JWT, cookies, mailer
│   └── oauth/    provider registry and the authorization-code client
├── prisma/       schema.prisma + migrations
├── validators/   Zod request schemas
├── docs/         OpenAPI document
├── types/        Express request augmentation (req.user)
├── scripts/      operator CLI (set-role)
├── generated/    Prisma client output (gitignored — regenerated from the schema)
├── app.ts        builds the Express app (no listening — this is what tests import)
└── server.ts     connects dependencies, listens, handles graceful shutdown
```

---

## Getting started

### Option A — everything in Docker

```bash
cp .env.example .env

# Generate the signing secret for access tokens and paste it into .env.
# (There is no refresh-token secret: refresh tokens are opaque random strings
# checked against the database, not signed JWTs.)
echo "JWT_ACCESS_SECRET=$(openssl rand -base64 48)"

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
cp .env.example .env            # then fill in JWT_ACCESS_SECRET as above
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
| `npm run set-role -- <email> <ROLE>` | Promote or demote a user (see [Access control](#access-control)) |

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
| `POST` | `/api/v1/auth/login` | — | Exchange credentials for an access token + refresh cookie. |
| `POST` | `/api/v1/auth/refresh` | Refresh token | Rotate the refresh token, get a new access token. |
| `POST` | `/api/v1/auth/logout` | Refresh token | End this session. Idempotent. |
| `POST` | `/api/v1/auth/logout-all` | Bearer | Revoke every session for the account. |
| `GET` | `/api/v1/auth/verify-email` | — | Confirm an address using the token from the emailed link. Single-use. |
| `POST` | `/api/v1/auth/resend-verification` | — | Request a fresh verification link. |
| `GET` | `/api/v1/auth/me` | Bearer | The authenticated user and their permissions. |
| `GET` | `/api/v1/auth/oauth` | — | Which social providers this deployment offers. |
| `GET` | `/api/v1/auth/oauth/:provider` | — | Begin social sign-in (302 to the provider). |
| `GET` | `/api/v1/auth/oauth/:provider/callback` | — | Provider redirect target. Not called by your code. |
| `GET` | `/api/v1/auth/oauth/linked` | Bearer | Providers linked to the caller's account. |
| `GET` | `/api/v1/users` | `users:read` | List users, paginated. |
| `GET` | `/api/v1/users/:id` | Self or `users:read` | Read one user. |
| `PATCH` | `/api/v1/users/:id/role` | `users:manage-roles` | Change a user's role. |
| `DELETE` | `/api/v1/users/:id` | `users:delete` | Delete a user. |
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

### Watching rotation and theft detection

`-c`/`-b` give curl a cookie jar, so it behaves like a browser holding the refresh cookie.

```bash
JAR=/tmp/auth-cookies.txt

curl -s -c $JAR -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"correct-horse-battery-staple"}' > /dev/null

# Copy the current refresh token — this stands in for one an attacker stole.
STOLEN=$(grep refresh_token $JAR | awk '{print $7}')

# The real user refreshes first. Works, and rotates the token.
curl -s -b $JAR -c $JAR -X POST http://localhost:3000/api/v1/auth/refresh | head -c 80

# The attacker now replays their copy. It has already been spent.
curl -s -X POST http://localhost:3000/api/v1/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$STOLEN\"}"
# => 401 {"error":{"code":"UNAUTHORIZED","message":"Refresh token has already been used; all sessions revoked"}}

# Every session for that account is now dead — including the real user's.
curl -s -b $JAR -X POST http://localhost:3000/api/v1/auth/refresh
# => 401 {"error":{"code":"UNAUTHORIZED","message":"Refresh token has been revoked"}}
```

The server log carries one `Refresh token reuse detected` warning for the actual theft,
and routine `Revoked refresh token presented` notices for the sessions the cascade cut.

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

## Social login

Google and GitHub, implemented as a hand-rolled authorization-code client rather than
Passport. Passport is built around sessions and serialise/deserialise hooks that a
stateless JWT service has no use for, and it hides the one step that matters most here —
the code-for-token exchange. Two providers of straight-line HTTP came to less code than
the strategy plumbing it would have replaced.

```
browser          this service                     provider
   │                  │                              │
   │ GET /auth/oauth/google                          │
   │─────────────────►│                              │
   │                  │ mint state → Redis + cookie  │
   │◄─ 302 ───────────│                              │
   │─────────────────────────────────────────────────►│  sign in, approve
   │◄─ 302 back with ?code=…&state=… ─────────────────│
   │─────────────────►│                              │
   │                  │ 1. state from URL == cookie? │
   │                  │    and still in Redis?       │
   │                  │ 2. POST code + client_secret ─────►│   server to server
   │                  │◄──────────── provider token ──────│
   │                  │ 3. GET profile ──────────────────►│
   │                  │◄──────── id, email, verified ─────│
   │                  │ 4. sign in / link / create   │
   │◄─ refresh cookie + access token ─│              │
```

Step 2 is server-to-server on purpose: the `code` passes through the browser where it can
be observed, but it is worthless without the client secret only this server holds. The
provider's token is used once to read the profile and then **discarded** — storing it
would mean holding a live credential to someone's Google account for no reason.

### `state`, and the attack it stops

Without `state`, an attacker can complete a flow with *their* provider account, capture
the resulting `code`, and trick a signed-in victim into loading the callback URL carrying
it. The victim's browser completes a sign-in they never started, silently attaching the
attacker's identity to the victim's session — login CSRF.

So the callback must prove it belongs to a flow *this browser* began. A random value goes
to the provider in the URL and into an httpOnly cookie; both must come back and match.
Redis holds the hash alongside the flow metadata, which adds what a cookie alone cannot:
single-use across every instance, and automatic expiry after ten minutes.

That cookie is `SameSite=Lax`, not `Strict` like the refresh cookie. The user returns via a
cross-site top-level navigation from google.com — and a Strict cookie is withheld on
exactly that, so the callback would never see the state it needs.

Every state failure — missing, mismatched, expired, replayed, wrong provider — returns the
same generic 401. Saying which one would tell an attacker how close they got.

### Account linking

Sign up with a password, later click "Sign in with Google", and you land on **one**
account. Three cases, in priority order:

| Situation | Outcome |
| --- | --- |
| This provider identity is already linked | `signed-in` — matched on the provider's stable user id |
| A local account has the same **verified** email | `linked` — an `OAuthAccount` row is added |
| Nothing matches | `created` — new user, `passwordHash` stays `null` |

Identities are matched on the provider's user id, never on email. People change their email
address, and matching on one would hand the account to whoever inherits that address next.

**Linking requires the provider to have verified the email**, and this is the sharp edge of
the whole feature. If linking happened on an unverified address, an attacker could register
`victim@example.com` at a provider with lax verification, sign in here, and be handed the
victim's existing account — a pre-account-takeover. An unverified address proves nothing
about who controls the mailbox, so that case is refused with a 403 and logged. GitHub makes
this concrete: `/user` hides the email unless it is public, so the verified address is read
from `/user/emails` and an account with none is turned away.

New OAuth accounts get `passwordHash: null` — exactly what the nullable column is for.
Inventing a random password nobody knows would leave an unusable credential on the account
and make "does this user have a password?" unanswerable.

### Configuring a provider

Each provider is optional and checked independently: a missing GitHub secret means that
button is not offered, and nothing else changes. Register the callback URL exactly as it
appears below — providers reject a `redirect_uri` that does not match.

```bash
# .env — Google: https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
#   redirect URI: http://localhost:3000/api/v1/auth/oauth/google/callback

# GitHub: https://github.com/settings/developers
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
#   redirect URI: http://localhost:3000/api/v1/auth/oauth/github/callback
```

```bash
curl http://localhost:3000/api/v1/auth/oauth
# => {"providers":["google"]}          # only what is configured

# Open this in a browser — it 302s to Google and sets the state cookie.
open http://localhost:3000/api/v1/auth/oauth/google
```

With `OAUTH_SUCCESS_REDIRECT_URL` unset, the callback returns the session as JSON, which is
what makes the flow demonstrable in an API-only service. Set it, and the callback instead
sets the refresh cookie and redirects there with **no token in the URL** — query strings
and fragments leak into browser history, server logs and `Referer` headers — leaving the
app to call `/auth/refresh` for its access token.

## Rate limiting and brute force

Two separate defences, because they stop different attacks.

**Per-IP rate limiting** keeps one machine from hammering an endpoint. Limits are set per
route rather than globally — nobody registers five accounts an hour from one address by
accident, but a browser tab left open overnight refreshes its token dozens of times. A
single global number would have to accommodate the busiest endpoint, which makes it
useless for the one that needs protecting.

| Endpoint | Limit | Window |
| --- | --- | --- |
| `POST /auth/register` | 5 | 1 hour |
| `POST /auth/login` | 10 (per IP **and** per account) | 5 min |
| `POST /auth/refresh` | 60 | 5 min |
| `POST /auth/resend-verification` | 3 (per IP and per account) | 1 hour |
| `GET /auth/verify-email` | 20 | 1 hour |
| `GET /auth/oauth/:provider` | 20 | 5 min |

Every response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`, so a
client can slow down before being cut off instead of discovering the limit by hitting it.
A 429 adds `Retry-After`, turning "try again later" into a number — otherwise retries
become their own small denial of service.

The limiter runs **first** on every route, ahead of validation. Putting it after would mean
an attacker still gets to spend the server's CPU parsing bodies and hashing passwords on
requests that were going to be rejected anyway. Malformed requests consume quota too, or
sending garbage would be a free pass.

**Per-account brute-force protection** handles what per-IP cannot: an attacker with a
botnet has thousands of addresses but still only needs to guess one account's password. So
consecutive failures are counted against the *account*, wherever they come from. Past five,
the account locks for 60 seconds, doubling with each further failure up to an hour.

Backoff rather than permanent lockout, deliberately — a lock that never lifts *is* the
attack, letting anyone who knows your email lock you out. Doubling delays make sustained
guessing hopeless (at the ceiling, 24 attempts a day) while someone who mistypes twice
notices nothing. A correct password clears the run, and a locked account is refused **even
with the right password** — an attacker who eventually guesses right still cannot get in.

Two details that matter:

- **Unknown emails are locked identically.** If only real accounts could be locked, the
  difference between 401 and 429 would reveal which addresses exist — undoing the
  enumeration work the login endpoint already does.
- **Emails are hashed into the Redis key.** A list of plaintext addresses currently under
  attack is a target in its own right.

**Why Redis, not memory.** With four containers behind a load balancer, an in-memory limit
of 10 is really 40, and an attacker spreading attempts across instances trips none of them.
Redis is the one place every instance agrees on, and its per-key TTL expires windows for
free. The counter uses a Lua script so `INCR` and `EXPIRE` are atomic: with two separate
commands, a process dying in between leaves a key with no expiry and that caller limited
forever.

**When Redis is down the limiter fails open** — availability over strictness, since a cache
outage should not lock every user out of the service. That is only defensible because of
the second line of defence: `/health/ready` reports Redis down, so the orchestrator pulls
the instance from rotation rather than leaving it serving unlimited login attempts.

## Access control

Routes declare the **capability** they need, not the role they expect. The tempting
shortcut — `if (user.role === 'ADMIN')` scattered through handlers — survives exactly
until the fourth role arrives, at which point "who may list users?" has to be re-answered
at every one of those sites, and the only way to find them is to grep.

| Permission | `USER` | `ADMIN` | `SUPERADMIN` |
| --- | :---: | :---: | :---: |
| `users:read` | | ✓ | ✓ |
| `users:manage-roles` | | | ✓ |
| `users:delete` | | | ✓ |

Higher roles are built by spreading the lower set, so inheritance is literal rather than
implied by a comparison like `role >= ADMIN`. Ordering roles on a number line works right
up to the first role that is not *more* powerful, merely *different* — a support agent who
may read users but never delete one does not fit anywhere on that line.

**Designed to outgrow this table.** The map in
[`src/config/permissions.ts`](src/config/permissions.ts) is static because static is
enough today and costs no query. Moving to customer-defined roles means replacing
`permissionsForRole` with a lookup over `Role`/`Permission`/`RolePermission` tables. Every
call site keeps asking the same question — "does this actor have `users:read`?" — so
nothing outside that one file changes. Routing all checks through a single function now,
before there is a reason to, is what makes that swap cheap later.

### The guard stack

```
authenticate          who are you?            401 if unanswerable
requireVerifiedEmail  is your address real?   403
requirePermission     may you do this?        403
validate              is the input sane?      400
controller            do it
```

Order is load-bearing, not cosmetic:

- **Authentication precedes authorization** — "may you" is unanswerable until "who are
  you" is settled.
- **Validation comes last of the guards.** A 400 handed to an unauthorized caller confirms
  which fields and formats the endpoint expects. They get a 403 instead, which tells them
  nothing. (The one exception is `/users/:id`, where the param is validated first because
  the ownership guard compares it against the caller's id.)
- **These run as middleware, not inside handlers.** A forbidden request never reaches
  business logic, the guard is visible in the route definition, and it cannot be forgotten
  halfway down a handler that later grew a second branch.

**401 vs 403 is a real distinction.** 401 means "I do not know who you are — authenticate
and retry"; 403 means "I know exactly who you are, and the answer is still no." Returning
401 for the second sends clients into a refresh-and-retry loop that can never succeed.

**Ownership is not a role.** "You may always read yourself" is a relationship between
actor and resource, which no role table can express.
[`requireSelfOrPermission`](src/middleware/authorize.ts) keeps that rule in one place
instead of having it reinvented, slightly differently, in each controller. It returns the
same 403 for a forbidden record and a non-existent one, so an unprivileged caller cannot
use the difference between 403 and 404 to discover which ids exist.

### Changing a role revokes the user's sessions

`role` travels inside the access token so authorization needs no database lookup — which
means a demoted admin keeps admin rights inside any token already issued. Revoking their
refresh tokens cannot claw those back, but it stops them being renewed, so the stale
privilege window closes at the access token's TTL (15 minutes) rather than the refresh
token's (7 days).

Shrinking it further means checking the role per request — exactly the round trip the
stateless token exists to avoid. Fifteen minutes of stale privilege is the price of that
speed, and it is a choice, not an oversight. There is a test asserting the behaviour
rather than pretending otherwise.

Self-demotion and self-deletion are both refused: the last superadmin dropping to `USER`
is how an organisation locks itself out of its own admin tooling.

### Creating the first admin

Changing a role requires `users:manage-roles`, which only a `SUPERADMIN` has — and a fresh
database has none. Something outside the HTTP API has to break that cycle:

```bash
npm run set-role -- you@example.com SUPERADMIN
# => you@example.com: USER -> SUPERADMIN (0 session(s) revoked)
```

Deliberately a manual operator action rather than a seed that runs at startup: an
auto-created admin with a known address is a backdoor in every environment it reaches.

Inside Docker, call the compiled script directly — the runtime image installs production
dependencies only, so `tsx` is not present:

```bash
docker compose exec app node dist/scripts/set-role.js you@example.com SUPERADMIN
```

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
| Refresh tokens stored as SHA-256 hashes, never in plaintext | [`src/services/refresh-token.service.ts`](src/services/refresh-token.service.ts) |
| Rotation on every use, with reuse escalating to full account revocation | [`src/services/refresh-token.service.ts`](src/services/refresh-token.service.ts) |
| Rotation is transactional, with a guard against concurrent double-spend | [`src/services/refresh-token.service.ts`](src/services/refresh-token.service.ts) |
| Refresh token kept out of JS reach: httpOnly, SameSite=Strict, path-scoped | [`src/lib/cookies.ts`](src/lib/cookies.ts) |
| Authorization checked in middleware, before any business logic runs | [`src/middleware/authorize.ts`](src/middleware/authorize.ts) |
| Role changes revoke the target's sessions, bounding stale privilege | [`src/services/user-admin.service.ts`](src/services/user-admin.service.ts) |
| Self-demotion and self-deletion refused, to prevent admin lockout | [`src/services/user-admin.service.ts`](src/services/user-admin.service.ts) |
| List endpoints paginated with a server-enforced ceiling | [`src/validators/user.validators.ts`](src/validators/user.validators.ts) |
| Unprivileged callers cannot distinguish 403 from 404 to probe for ids | [`src/middleware/authorize.ts`](src/middleware/authorize.ts) |
| OAuth `state` bound to the browser, single-use, expiring — blocks login CSRF | [`src/services/oauth-state.service.ts`](src/services/oauth-state.service.ts) |
| Account linking refused on a provider-unverified email (pre-account-takeover) | [`src/services/oauth.service.ts`](src/services/oauth.service.ts) |
| Provider tokens used once for the profile, never stored | [`src/controllers/oauth.controller.ts`](src/controllers/oauth.controller.ts) |
| OAuth identities keyed on the provider's stable user id, not email | [`src/services/oauth.service.ts`](src/services/oauth.service.ts) |
| Minimum scopes requested (no profile, name or avatar) | [`src/lib/oauth/providers.ts`](src/lib/oauth/providers.ts) |
| Unknown request fields stripped before reaching Prisma (no `role` injection) | [`src/middleware/validate.ts`](src/middleware/validate.ts) |
| Every login attempt recorded for the audit trail | [`src/services/auth.service.ts`](src/services/auth.service.ts) |
| Email links built from configured `APP_BASE_URL`, never the `Host` header | [`src/config/env.ts`](src/config/env.ts) |
| Per-IP rate limiting on every unauthenticated endpoint, ahead of validation | [`src/middleware/rate-limit.ts`](src/middleware/rate-limit.ts) |
| Per-account brute-force lockout with exponential backoff | [`src/services/brute-force.service.ts`](src/services/brute-force.service.ts) |
| Rate-limit counters atomic (Lua) and shared across instances | [`src/lib/rate-limit.ts`](src/lib/rate-limit.ts) |
| Emails hashed into rate-limit keys, never stored in Redis as plaintext | [`src/middleware/rate-limit.ts`](src/middleware/rate-limit.ts) |
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
npm test                              # 144 tests
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
- Rotation: the chain is recorded rather than deleted, a replayed token revokes every
  session for that user, other users are untouched, and expired or unknown tokens are
  rejected without raising the theft alarm
- Logout: idempotent, scoped to one session, and honest about the access token staying
  valid until it expires; `logout-all` requires a real access token, not just a cookie

- Access control: unauthenticated gets 401 while under-privileged gets 403, an admin
  refused a superadmin-only action, an unverified admin refused outright, 403 returned
  ahead of 400 so the schema is not disclosed, role change killing the target's sessions,
  self-demotion and self-deletion blocked, and deletion cascading to refresh tokens while
  the login audit trail survives

- OAuth: forged, absent, replayed and cross-provider `state` all rejected; cancelled
  sign-in; account created with a null password; the same identity signing back in without
  duplicating; linking to an existing password account and leaving that password working;
  **linking refused on an unverified provider email**; case-insensitive email matching; two
  providers linked to one account; an unconfigured provider 404ing without affecting the
  configured one

The two functions that talk to Google and GitHub over the network are mocked; state
handling, linking rules and session issuing all run for real, so the tests stay offline and
deterministic without faking away the logic worth testing.

- Rate limiting: headers present on success, 429 with `Retry-After` past the limit,
  malformed requests still consuming quota, separate buckets per endpoint, exponential
  backoff lengthening per failure, a locked account refused even with the correct
  password, unknown emails locked identically, other accounts unaffected, and a locked
  request rejected before any Argon2 work happens

---

## Roadmap

- [x] **1. Scaffold** — Express + TypeScript + Prisma + Redis + Docker Compose, health checks, error handling
- [x] **2. Email/password auth** — register, login, JWT issuing, email verification (stubbed mailer)
- [x] **3. Refresh token rotation** — reuse detection, logout, revocation
- [x] **4. RBAC** — permission middleware, protected user-management routes
- [x] **5. OAuth2** — Google + GitHub, account linking
- [x] **6. Rate limiting** — per-IP and per-account, brute-force protection
- [ ] **7. Docs** — OpenAPI spec + auth flow diagram
- [ ] **8. Stretch** — TOTP-based 2FA

---

## Notes

- `npm audit` reports advisories in `mysql2`, a transitive dependency of the Prisma CLI.
  This service uses PostgreSQL, so that driver is never loaded at runtime.
- The `prisma` CLI is pinned to 7.10.0 rather than `latest`, because npm's `latest` tag for
  it currently points at an 8.0.0 release candidate that does not match `@prisma/client`.
