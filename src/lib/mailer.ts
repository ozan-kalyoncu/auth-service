import { logger } from './logger.js';

/**
 * Stubbed email delivery.
 *
 * Sending real email needs a provider (SES, Postmark, Resend), a verified
 * sending domain, and SPF/DKIM records -- none of which demonstrate anything
 * about auth design. So this logs what WOULD be sent, and the rest of the
 * service is written as if delivery were real: the verification link is never
 * returned in an API response, exactly as it would not be in production.
 *
 * Swapping this for a real provider means changing this one file.
 */
export interface Email {
  to: string;
  subject: string;
  body: string;
}

export async function sendEmail(email: Email): Promise<void> {
  logger.info(
    { to: email.to, subject: email.subject, body: email.body },
    '[stub mailer] email would be sent',
  );

  // Async signature on purpose: a real provider call returns a promise, and every
  // caller already awaits it, so swapping the implementation changes nothing here.
  await Promise.resolve();
}

/**
 * Sent when someone tries to register with an address that already has an
 * account. It is what lets /register stay silent about whether an email exists:
 * the notice goes to the address's real owner, not to whoever submitted the form.
 */
export function buildDuplicateRegistrationEmail(to: string): Email {
  return {
    to,
    subject: 'Someone tried to create an account with your email',
    body: [
      'An account with this email address already exists, so no new account was created.',
      '',
      'If this was you, sign in instead -- or reset your password if you have forgotten it.',
      'If it was not you, no action is needed; nothing about your account has changed.',
    ].join('\n'),
  };
}

export function buildVerificationEmail(to: string, verificationUrl: string): Email {
  return {
    to,
    subject: 'Verify your email address',
    body: [
      'Welcome! Confirm your email address to finish setting up your account:',
      '',
      verificationUrl,
      '',
      'This link expires in 24 hours. If you did not create an account, ignore this email.',
    ].join('\n'),
  };
}
