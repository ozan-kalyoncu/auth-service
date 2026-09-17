# Auth & Authorization Microservice

## Purpose

This is a portfolio project by a full-stack developer (5 years WordPress/Shopify/React,
math engineering background) aiming to prove production-grade backend skills for job
applications. This project specifically targets a gap: the developer's CV currently has
no project demonstrating authentication/authorization system design, which is one of the
first things backend interviews probe.

**Goal:** a standalone, deployable auth service — not a login form bolted onto a frontend.
It should look and behave like something a real company would run as a shared internal
service that other applications authenticate against.

## Tech Stack

Keep this consistent with the developer's other backend projects (E-commerce Admin API) —
stack consistency across the portfolio matters more than using the "best" tool for each job.

- **Runtime:** Node.js + TypeScript
- **Framework:** Express
- **Database:** PostgreSQL
- **ORM:** Prisma
- **Cache / session store:** Redis (refresh tokens, rate limiting)
- **Auth:** JWT (short-lived access tokens) + rotating refresh tokens
- **OAuth2:** Google and GitHub login via Passport.js or a lightweight OAuth client
- **Validation:** Zod
- **Testing:** Vitest or Jest + Supertest for integration tests
- **Containerization:** Docker + docker-compose (Postgres + Redis + app)
- **Docs:** OpenAPI/Swagger spec generated from routes

## Core Features (in priority order)

1. **Email/password auth**
   - Register, login, logout
   - Password hashing with bcrypt/argon2
   - Email verification flow (can be stubbed/logged instead of real email sending)
2. **JWT access + refresh token flow**
   - Short-lived access token (~15 min)
   - Refresh token rotation with reuse detection (refresh tokens stored hashed in Redis or DB)
   - Revocation / logout invalidates refresh token
3. **Role-Based Access Control (RBAC)**
   - Roles: e.g. `user`, `admin`, `superadmin`
   - Middleware to protect routes by role
   - Permissions model that could scale beyond 3 hardcoded roles (design for it, don't
     necessarily build it all now)
4. **OAuth2 social login**
   - Google and GitHub providers
   - Account linking (same email via password vs OAuth should not create duplicate users)
5. **Rate limiting**
   - Per-IP and per-account rate limiting on login/register endpoints (Redis-backed)
6. **Security hardening**
   - Helmet, CORS config, input validation on every endpoint
   - Brute-force protection (account lockout or exponential backoff after failed attempts)

## Prisma Schema (v1)

```prisma
model User {
  id              String   @id @default(cuid())
  email           String   @unique
  passwordHash    String?  // null if the user only ever signed up via OAuth
  role            Role     @default(USER)
  isEmailVerified Boolean  @default(false)
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt

  oauthAccounts   OAuthAccount[]
  refreshTokens   RefreshToken[]
  loginAttempts   LoginAttempt[]
}

enum Role {
  USER
  ADMIN
  SUPERADMIN
}

// One row per external identity linked to a User. Lets the same user log in
// via password AND Google AND GitHub without creating duplicate accounts.
model OAuthAccount {
  id             String   @id @default(cuid())
  provider       String   // "google" | "github"
  providerUserId String   // the ID that provider assigns to this user
  userId         String
  user           User     @relation(fields: [userId], references: [id])
  createdAt      DateTime @default(now())

  @@unique([provider, providerUserId])
}

// Refresh tokens are never stored in plaintext -- only a hash of the token.
// Rotation chain: when a token is used, it's marked revoked and replacedBy
// points at the new token's id, so token reuse (a sign of theft) is detectable.
model RefreshToken {
  id         String    @id @default(cuid())
  tokenHash  String    @unique
  userId     String
  user       User      @relation(fields: [userId], references: [id])
  expiresAt  DateTime
  revokedAt  DateTime?
  replacedBy String?
  createdAt  DateTime  @default(now())
}

// Every login attempt, successful or not, so brute-force protection and
// rate limiting have something real to check against.
model LoginAttempt {
  id        String   @id @default(cuid())
  userId    String?
  user      User?    @relation(fields: [userId], references: [id])
  ip        String
  success   Boolean
  createdAt DateTime @default(now())
}
```

Notes for the agent:
- `passwordHash` is nullable specifically to support OAuth-only accounts (see account
  linking in Core Features). Don't make it required.
- `RefreshToken.replacedBy` is what makes rotation auditable — always set it when
  issuing a replacement token, never just delete the old row.
- Add indexes on `RefreshToken.userId`, `LoginAttempt.ip`, and `LoginAttempt.createdAt`
  once query patterns are clear (not required for the first migration).

## Explicitly Out of Scope (v1)

- Frontend UI (this is an API-only service; Postman/curl/Swagger UI is the interface)
- Multi-tenancy
- Passwordless/magic-link auth
- SMS-based 2FA (email-based 2FA/TOTP is a good v2 stretch goal, not v1)

## Project Structure

```
auth-service/
├── src/
│   ├── config/          # env config, constants
│   ├── routes/          # route definitions
│   ├── controllers/     # request handlers
│   ├── services/        # business logic (auth, token, user)
│   ├── middleware/       # auth guard, RBAC guard, rate limiter, error handler
│   ├── prisma/           # schema.prisma, migrations
│   ├── lib/              # redis client, jwt helpers, oauth client setup
│   ├── validators/       # zod schemas
│   └── app.ts / server.ts
├── tests/
│   ├── unit/
│   └── integration/
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── README.md
```

## Conventions

- **Educational comments required.** The developer is frontend-focused (WordPress/Shopify/
  React) and is building this project specifically to learn backend system design — not
  just to get code that works. For every non-trivial backend concept, add a short comment
  explaining *why*, not just *what*:
  - Why refresh tokens are hashed before storage, not stored raw
  - Why access tokens are short-lived and refresh tokens are long-lived
  - What "rotation" and "reuse detection" actually protect against (a stolen refresh token)
  - Why RBAC middleware runs before the controller, not inside it
  - Why rate limiting lives in Redis instead of in-memory
  - Any place a decision trades off complexity vs. security vs. performance — explain the
    trade-off, not just the choice
  Keep these comments concise (2–4 lines) and placed right above the relevant code, not as
  a wall of text at the top of the file. Assume strong JS/React fundamentals but no prior
  backend security or systems-design experience.
- All endpoints return consistent JSON error shapes: `{ error: { code, message } }`
- No secrets committed — everything through `.env`, with `.env.example` kept up to date
- Every new endpoint needs: a Zod validator, an integration test, and an OpenAPI entry
- Prefer small, composable middleware over logic embedded in controllers
- Write commit messages and PR-style descriptions as if this were a real team project —
  this repo is a portfolio piece and may be reviewed by an interviewer

## Milestones

1. Project scaffold: Express + TypeScript + Prisma + Docker Compose running locally
2. Email/password register + login + JWT issuing
3. Refresh token rotation + logout/revocation
4. RBAC middleware + protected example routes
5. OAuth2 (Google, GitHub) + account linking
6. Rate limiting + brute-force protection
7. OpenAPI docs + README with architecture diagram and setup instructions
8. (Stretch) TOTP-based 2FA

## Definition of Done (for the README / portfolio presentation)

- `docker-compose up` gets the whole thing running with one command
- README includes: architecture overview, a diagram of the auth flow (access/refresh
  token lifecycle), setup steps, and example requests for every endpoint
- Test suite covers the auth flow end-to-end, not just happy paths (expired tokens,
  reused refresh tokens, wrong roles, rate-limit triggering)