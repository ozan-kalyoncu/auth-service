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
    version: '0.5.0',
    description:
      'Authentication and authorization service. Short-lived JWT access tokens paired with ' +
      'rotating, revocable refresh tokens that detect reuse, permission-based access control, ' +
      'and Google/GitHub sign-in with account linking.',
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
      // 403, not 401: we know exactly who the caller is, and the answer is still
      // no. Returning 401 here would send clients into a pointless
      // refresh-and-retry loop that can never succeed.
      Forbidden: {
        description: 'Authenticated, but lacking the required permission',
        content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
      },
      NotFound: {
        description: 'No such resource',
        content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
      },
      RateLimited: {
        description:
          'Rate limit exceeded, or the account is temporarily locked after repeated failed ' +
          'logins. Every response carries RateLimit-Limit / RateLimit-Remaining / ' +
          'RateLimit-Reset; this one also carries Retry-After.',
        headers: {
          'Retry-After': {
            description: 'Seconds to wait before retrying',
            schema: { type: 'integer' },
          },
          'RateLimit-Remaining': {
            description: 'Requests left in the current window',
            schema: { type: 'integer' },
          },
        },
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
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },

    '/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Exchange email and password for an access token',
        description:
          'An unknown email and a wrong password produce an identical 401, and take ' +
          'comparable time, so this endpoint cannot be used to discover valid addresses. ' +
          'Rate limited per IP and per account; repeated failures lock the account with ' +
          'exponential backoff, and a locked account is refused even with the right password.',
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
          429: { $ref: '#/components/responses/RateLimited' },
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
          429: { $ref: '#/components/responses/RateLimited' },
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
          429: { $ref: '#/components/responses/RateLimited' },
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
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },

    '/auth/me': {
      get: {
        tags: ['Auth'],
        summary: 'Return the authenticated user and their permissions',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'The current user',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/PublicUser' },
                    permissions: {
                      type: 'array',
                      items: { type: 'string' },
                      description:
                        'What this caller may do. For rendering UI only -- enforcement is ' +
                        'server-side, in middleware.',
                      example: ['users:read'],
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },

    '/auth/oauth': {
      get: {
        tags: ['OAuth'],
        summary: 'List the social providers this deployment offers',
        description:
          'Only providers with credentials configured are listed. Each is independent: a ' +
          'missing GitHub secret leaves Google and password login unaffected.',
        responses: {
          200: {
            description: 'Available providers',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    providers: {
                      type: 'array',
                      items: { type: 'string', enum: ['google', 'github'] },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },

    '/auth/oauth/linked': {
      get: {
        tags: ['OAuth'],
        summary: 'List the providers linked to the caller',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Linked providers',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { providers: { type: 'array', items: { type: 'string' } } },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },

    '/auth/oauth/{provider}': {
      get: {
        tags: ['OAuth'],
        summary: 'Begin a social sign-in',
        description:
          'A browser endpoint, not an API call: point a "Sign in with Google" link here and ' +
          'the response is a 302 to the provider. Also sets a short-lived httpOnly `state` ' +
          'cookie that the callback requires, which is what proves the callback belongs to a ' +
          'flow this browser started.',
        parameters: [
          {
            name: 'provider',
            in: 'path',
            required: true,
            schema: { type: 'string', enum: ['google', 'github'] },
          },
        ],
        responses: {
          302: { description: "Redirect to the provider's consent screen" },
          429: { $ref: '#/components/responses/RateLimited' },
          404: {
            description: 'Unknown provider, or one this deployment has no credentials for',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },

    '/auth/oauth/{provider}/callback': {
      get: {
        tags: ['OAuth'],
        summary: 'Provider redirect target',
        description:
          'Called by the provider, not by your code. Validates `state` against the cookie, ' +
          'exchanges the code for a provider token server-to-server, reads the profile, then ' +
          'signs in / links / creates the local account. Sets the refresh cookie. Returns JSON ' +
          'when OAUTH_SUCCESS_REDIRECT_URL is unset, otherwise redirects there with no token ' +
          'in the URL.',
        parameters: [
          {
            name: 'provider',
            in: 'path',
            required: true,
            schema: { type: 'string', enum: ['google', 'github'] },
          },
          { name: 'code', in: 'query', schema: { type: 'string' } },
          { name: 'state', in: 'query', schema: { type: 'string' } },
          {
            name: 'error',
            in: 'query',
            schema: { type: 'string' },
            description: 'Present when the user cancelled or denied at the provider',
          },
        ],
        responses: {
          200: {
            description: 'Signed in',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/PublicUser' },
                    outcome: {
                      type: 'string',
                      enum: ['signed-in', 'linked', 'created'],
                      description: 'Whether an existing identity was used, linked, or created',
                    },
                    accessToken: { type: 'string' },
                    tokenType: { type: 'string', enum: ['Bearer'] },
                    expiresIn: { type: 'integer', example: 900 },
                  },
                },
              },
            },
          },
          302: { description: 'Redirect to OAUTH_SUCCESS_REDIRECT_URL when configured' },
          401: {
            description: 'Invalid, expired or replayed state; cancelled at the provider',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          403: {
            description:
              'The email is already registered here and the provider has not verified it, ' +
              'so linking is refused (pre-account-takeover defence).',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },

    '/users': {
      get: {
        tags: ['Users'],
        summary: 'List users',
        description:
          'Requires the users:read permission (ADMIN and above) and a verified email address. ' +
          'Paginated, with limit capped at 100 server-side.',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
          },
          { name: 'offset', in: 'query', schema: { type: 'integer', minimum: 0, default: 0 } },
        ],
        responses: {
          200: {
            description: 'A page of users',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    users: { type: 'array', items: { $ref: '#/components/schemas/PublicUser' } },
                    total: { type: 'integer' },
                    limit: { type: 'integer' },
                    offset: { type: 'integer' },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          403: { $ref: '#/components/responses/Forbidden' },
        },
      },
    },

    '/users/{id}': {
      get: {
        tags: ['Users'],
        summary: 'Read one user',
        description:
          'Allowed if the id is your own, or if you hold users:read. Ownership is a ' +
          'relationship between actor and resource, which a role alone cannot express.',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'The user',
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
          403: { $ref: '#/components/responses/Forbidden' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },

      delete: {
        tags: ['Users'],
        summary: 'Delete a user',
        description:
          'Requires users:delete (SUPERADMIN). Refresh tokens and linked OAuth accounts ' +
          'cascade with the row. You cannot delete your own account here.',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          204: { description: 'Deleted' },
          401: { $ref: '#/components/responses/Unauthorized' },
          403: { $ref: '#/components/responses/Forbidden' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },

    '/users/{id}/role': {
      patch: {
        tags: ['Users'],
        summary: "Change a user's role",
        description:
          'Requires users:manage-roles (SUPERADMIN). Changing a role revokes that user\'s ' +
          'refresh tokens, so their old role cannot outlive the current access token. ' +
          'Changing your own role is refused, to prevent locking the organisation out.',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['role'],
                properties: { role: { type: 'string', enum: ['USER', 'ADMIN', 'SUPERADMIN'] } },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Updated user',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { user: { $ref: '#/components/schemas/PublicUser' } },
                },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          401: { $ref: '#/components/responses/Unauthorized' },
          403: { $ref: '#/components/responses/Forbidden' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
  },
} as const;
