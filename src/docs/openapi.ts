/**
 * OpenAPI description of the API, served as JSON at /api/v1/openapi.json.
 *
 * Written by hand rather than generated from the routes. Generating it from
 * Express requires decorators or a route-scanning library that mostly infers
 * shapes it cannot actually know; hand-writing keeps the contract explicit and
 * reviewable, at the cost of having to update it alongside each endpoint --
 * which the project conventions require anyway.
 *
 * Milestone 7 mounts Swagger UI on top of this document.
 */

const errorResponse = {
  type: 'object',
  properties: {
    error: {
      type: 'object',
      required: ['code', 'message'],
      properties: {
        code: {
          type: 'string',
          enum: [
            'VALIDATION_ERROR',
            'UNAUTHORIZED',
            'FORBIDDEN',
            'NOT_FOUND',
            'CONFLICT',
            'RATE_LIMITED',
            'INTERNAL_ERROR',
          ],
        },
        message: { type: 'string' },
        details: { type: 'array', items: { type: 'object' } },
      },
    },
  },
} as const;

const publicUser = {
  type: 'object',
  required: ['id', 'email', 'role', 'isEmailVerified', 'createdAt'],
  properties: {
    id: { type: 'string', example: 'clx0a1b2c3d4e5f6g7h8i9j0' },
    email: { type: 'string', format: 'email' },
    role: { type: 'string', enum: ['USER', 'ADMIN', 'SUPERADMIN'] },
    isEmailVerified: { type: 'boolean' },
    createdAt: { type: 'string', format: 'date-time' },
  },
} as const;

export const openApiDocument = {
  openapi: '3.1.0',
  info: {
    title: 'Auth Service API',
    version: '0.3.0',
    description:
      'Authentication and authorization service. Short-lived JWT access tokens paired with ' +
      'rotating, revocable refresh tokens that detect reuse.',
  },
  servers: [{ url: '/api/v1' }],

  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Access token returned by POST /auth/login.',
      },
    },
    schemas: { Error: errorResponse, PublicUser: publicUser },
    responses: {
      ValidationError: {
        description: 'Request failed validation',
        content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
      },
      Unauthorized: {
        description: 'Missing, malformed, expired or invalid credentials',
        content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
      },
    },
  },

  paths: {
    '/health/live': {
      get: {
        tags: ['Health'],
        summary: 'Liveness probe',
        description:
          'Reports that the process is running. Touches no dependencies on purpose, so a ' +
          'database outage does not cause an orchestrator to restart a healthy process.',
        responses: {
          200: {
            description: 'Process is alive',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { status: { type: 'string', enum: ['ok'] } },
                },
              },
            },
          },
        },
      },
    },

    '/health/ready': {
      get: {
        tags: ['Health'],
        summary: 'Readiness probe',
        description: 'Pings Postgres and Redis. Returns 503 when either is unreachable.',
        responses: {
          200: { description: 'All dependencies reachable' },
          503: { description: 'A dependency is down; do not route traffic here' },
        },
      },
    },

    '/auth/register': {
      post: {
        tags: ['Auth'],
        summary: 'Register a new account',
        description:
          'Always returns 202 with the same body, whether or not the email was already ' +
          'registered. This is deliberate: a distinct "email taken" response would let ' +
          'anyone enumerate which addresses have accounts. When the address already ' +
          'exists, a notice is emailed to its owner instead.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'password'],
                properties: {
                  email: { type: 'string', format: 'email' },
                  password: { type: 'string', minLength: 12, maxLength: 128 },
                },
              },
            },
          },
        },
        responses: {
          202: { description: 'Request accepted; a verification link may have been sent' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },

    '/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Exchange email and password for an access token',
        description:
          'An unknown email and a wrong password produce an identical 401, and take ' +
          'comparable time, so this endpoint cannot be used to discover valid addresses.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'password'],
                properties: {
                  email: { type: 'string', format: 'email' },
                  password: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description:
              'Authenticated. The refresh token is set as an httpOnly cookie and is ' +
              'deliberately absent from this body, where page scripts could read it.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/PublicUser' },
                    accessToken: { type: 'string' },
                    tokenType: { type: 'string', enum: ['Bearer'] },
                    expiresIn: {
                      type: 'integer',
                      description: 'Seconds until the access token expires',
                      example: 900,
                    },
                  },
                },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },

    '/auth/refresh': {
      post: {
        tags: ['Auth'],
        summary: 'Rotate the refresh token and get a new access token',
        description:
          'Reads the refresh token from the httpOnly cookie, or from the body for clients ' +
          'without a cookie jar. Every call invalidates the token it was given and issues a ' +
          'replacement. Presenting an already-used token is treated as theft: all of that ' +
          "user's sessions are revoked and the call fails with 401.",
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  refreshToken: {
                    type: 'string',
                    description: 'Only needed when the cookie is not sent.',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Rotated. New refresh token is set as an httpOnly cookie.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/PublicUser' },
                    accessToken: { type: 'string' },
                    tokenType: { type: 'string', enum: ['Bearer'] },
                    expiresIn: { type: 'integer', example: 900 },
                  },
                },
              },
            },
          },
          401: {
            description: 'Token missing, unknown, expired, or already used (reuse detected)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },

    '/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'End the current session',
        description:
          'Revokes the presented refresh token and clears the cookie. Idempotent: logging out ' +
          'twice, or with no token at all, still returns 204. The access token already issued ' +
          'stays valid until it expires -- the accepted cost of stateless tokens.',
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: { refreshToken: { type: 'string' } },
              },
            },
          },
        },
        responses: { 204: { description: 'Session ended' } },
      },
    },

    '/auth/logout-all': {
      post: {
        tags: ['Auth'],
        summary: 'Sign out of every device',
        description:
          'Revokes every live refresh token for the account. Requires a valid access token, ' +
          'since it acts on the whole account rather than one session.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'All sessions revoked',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { sessionsRevoked: { type: 'integer', example: 3 } },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },

    '/auth/verify-email': {
      get: {
        tags: ['Auth'],
        summary: 'Confirm an email address',
        description:
          'Opened from the link in the verification email. The token is single-use: it is ' +
          'read and deleted atomically, so the same link cannot be replayed.',
        parameters: [
          {
            name: 'token',
            in: 'query',
            required: true,
            schema: { type: 'string' },
            description: 'Token from the emailed link',
          },
        ],
        responses: {
          200: { description: 'Email address verified' },
          400: {
            description: 'Token missing, unknown, already used, or expired',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },

    '/auth/resend-verification': {
      post: {
        tags: ['Auth'],
        summary: 'Request a fresh verification link',
        description:
          'Returns 202 for unknown, unverified and already-verified addresses alike, so it ' +
          'cannot be used to probe account existence or verification status.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email'],
                properties: { email: { type: 'string', format: 'email' } },
              },
            },
          },
        },
        responses: {
          202: { description: 'Request accepted' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },

    '/auth/me': {
      get: {
        tags: ['Auth'],
        summary: 'Return the authenticated user',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'The current user',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { user: { $ref: '#/components/schemas/PublicUser' } },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
  },
} as const;
