# Multi-stage build. The final image ships only compiled JS and production
# dependencies -- no TypeScript compiler, no test tooling, no source. Smaller
# image, faster pulls, and a smaller attack surface in the running container.

# ---------------------------------------------------------------------------
# Stage 1: build (needs devDependencies: typescript)
# ---------------------------------------------------------------------------
FROM node:22-slim AS build

WORKDIR /app

# Copy manifests first, on their own. Docker caches each layer, so dependencies
# are only reinstalled when these two files change -- editing source code does
# not trigger a fresh npm ci.
COPY package.json package-lock.json ./
RUN npm ci

COPY prisma.config.ts tsconfig.json ./
COPY src ./src

# Generate the typed Prisma client into src/generated, then compile everything
# (application code plus that generated client) to dist/.
RUN npx prisma generate
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM node:22-slim AS runtime

ENV NODE_ENV=production

WORKDIR /app

# --omit=dev drops typescript, vitest and friends. The Prisma CLI is a *runtime*
# dependency here on purpose: the container runs `prisma migrate deploy` on
# startup, so the CLI has to exist in this image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Compiled application, including the generated Prisma client under dist/generated.
COPY --from=build /app/dist ./dist

# The schema and migration files are read at startup by `prisma migrate deploy`,
# and prisma.config.ts is what points the CLI at them.
COPY prisma.config.ts ./
COPY src/prisma ./src/prisma

# Run as a non-root user. If an attacker achieves code execution inside the
# container, they land as an unprivileged user rather than root.
USER node

EXPOSE 3000

CMD ["node", "dist/server.js"]
