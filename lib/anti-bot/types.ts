import type { AppSettings } from '../api/model';

/** The covered call an anti-bot value is produced for. */
export type AntiBotOperation =
  | 'sign-in'
  | 'sign-up'
  | 'passwordless.start'
  | 'passkey.register'
  | 'passkey.authenticate'
  | 'password-reset.send'
  | 'federated.start'
  | 'session.exchange'
  | 'device.authenticate'
  | 'device.passkey.start';

/** What a token provider is asked for. `action` is always `'passflow_auth'`. */
export type AntiBotTokenContext = { action: 'passflow_auth'; operation: AntiBotOperation };

/**
 * The customer's own anti-bot provider (Turnstile, hCaptcha, reCAPTCHA): resolves with a token
 * the server verifies with that provider. A function with no parameters is accepted too.
 */
export type AntiBotTokenProvider = (context: AntiBotTokenContext) => Promise<string>;

/** The device verification page's context for `POST /oidc/device/anti-bot/challenge`. */
export type AntiBotDeviceContext = { userCode: string; csrfToken: string };

/** The bot mode and provider an anti-bot value is produced for. */
export type AntiBotAppSettings = Pick<AppSettings, 'bot_mode' | 'anti_bot'>;

export type AntiBotTokenRequest = {
  operation: AntiBotOperation;
  /** Email, username or phone, sent with the challenge request; used by the server for difficulty only. */
  identifier?: string;
  /** Bot mode and provider when not this app's `/app/settings` (the device page: `/oidc/device/info`). */
  settings?: AntiBotAppSettings;
  device?: AntiBotDeviceContext;
};
