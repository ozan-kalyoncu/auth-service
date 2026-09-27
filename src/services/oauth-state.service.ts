import { redis } from '../lib/redis.js';
import { generateSecureToken, hashToken, safeCompare } from '../lib/crypto.js';
import { OAUTH_STATE_TTL_SECONDS } from '../config/constants.js';
import type { ProviderName } from '../lib/oauth/providers.js';

/**
 * The `state` parameter, and why it is not optional.
 *
 * Without it, an attacker can complete an OAuth flow with THEIR provider account,
 * capture the resulting `code`, and then trick a logged-in victim into loading
 * the callback URL carrying that code. The victim's browser completes a sign-in
 * the victim never started, silently linking the attacker's identity to the
 * victim's session -- login CSRF.
 *
 * The defence is to prove the callback belongs to a flow THIS browser began:
 *   - a random state travels to the provider and comes back in the URL;
 *   - the same value is also put in a cookie that only this browser holds;
 *   - on the callback both must be present and equal.
 *
 * Redis holds the hash of that state alongside the flow's metadata, which adds
 * two things a cookie alone cannot: the state is single-use across every
 * instance of the service, and it expires on its own after ten minutes.
 */
export interface OAuthFlowState {
  provider: ProviderName;
}

function stateKey(state: string): string {
  return `oauth-state:${hashToken(state)}`;
}

/** Starts a flow: returns the raw state to send to the provider and store in a cookie. */
export async function issueState(provider: ProviderName): Promise<string> {
  const state = generateSecureToken();
  const payload: OAuthFlowState = { provider };

  await redis.set(stateKey(state), JSON.stringify(payload), 'EX', OAUTH_STATE_TTL_SECONDS);

  return state;
}

/**
 * Validates and consumes the state on the callback.
 *
 * Returns null on any failure -- missing, mismatched, unknown, expired, or for a
 * different provider than the callback claims. The caller turns that into one
 * generic error, because distinguishing "expired" from "forged" tells an
 * attacker which half of their attempt was wrong.
 */
export async function consumeState(
  provider: ProviderName,
  stateFromQuery: string | undefined,
  stateFromCookie: string | undefined,
): Promise<OAuthFlowState | null> {
  if (!stateFromQuery || !stateFromCookie) return null;

  // Constant-time: this is a secret comparison like any other.
  if (!safeCompare(stateFromQuery, stateFromCookie)) return null;

  // GETDEL makes the state single-use atomically -- a replayed callback finds
  // nothing, even if two requests arrive at the same moment.
  const raw = await redis.getdel(stateKey(stateFromQuery));

  if (!raw) return null;

  const parsed = JSON.parse(raw) as OAuthFlowState;

  // The state was issued for a specific provider; refuse to let a state minted
  // for Google be redeemed at the GitHub callback.
  if (parsed.provider !== provider) return null;

  return parsed;
}
