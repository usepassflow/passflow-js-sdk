/**
 * Storage Manager
 *
 * Abstraction layer over browser localStorage for token and data persistence.
 * Supports custom storage implementations for testing and alternative platforms.
 * Handles key prefixing for multi-app scenarios.
 *
 * @module storage
 */

import { TokenType } from '../token';
import { parseToken } from '../token/service';
import { TokenDeliveryMode, Tokens } from '../types';

export type Storage = {
  setItem: (key: string, value: string) => void;
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
};

export interface StorageManagerParams {
  storage?: Storage;
  prefix?: string;
  /** The app the stored tokens must be issued for; see `setAppId()`. */
  appId?: string;
}

// Unprefixed key names; with a storage prefix the key is `${prefix}_${name}`.
const SCOPES_KEY = 'tokens_scopes';
const DEVICE_ID_KEY = 'passflowDeviceId';
const INVITATION_TOKEN_KEY = 'passflowInvitationToken';
const PREVIOUS_REDIRECT_URL_KEY = 'passflowPreviousRedirectUrl';

export class StorageManager {
  private keyStoragePrefix = '';
  readonly scopes: string;
  readonly deviceId: string;
  readonly invitationToken: string;
  readonly previousRedirectUrl: string;

  // Namespaced keys for cookie mode support
  private readonly STORAGE_PREFIX = 'passflow_';
  private readonly ID_TOKEN_KEY = `${this.STORAGE_PREFIX}id_token`;
  private readonly CSRF_TOKEN_KEY = `${this.STORAGE_PREFIX}csrf_token`;
  private readonly DELIVERY_MODE_KEY = `${this.STORAGE_PREFIX}delivery_mode`;

  private storage: Storage;
  private appId: string | undefined;

  constructor({ storage, prefix, appId }: StorageManagerParams = {}) {
    this.storage = storage ?? localStorage;
    this.keyStoragePrefix = prefix ? `${prefix}_` : '';
    this.scopes = `${this.keyStoragePrefix}${SCOPES_KEY}`;
    this.deviceId = `${this.keyStoragePrefix}${DEVICE_ID_KEY}`;
    this.invitationToken = `${this.keyStoragePrefix}${INVITATION_TOKEN_KEY}`;
    this.previousRedirectUrl = `${this.keyStoragePrefix}${PREVIOUS_REDIRECT_URL_KEY}`;
    this.appId = appId || undefined;
  }

  /**
   * Sets the app the stored tokens must be issued for. A stored token whose `aud` does not name
   * this app reads as absent, so another app's session on the same origin never counts as this
   * app's. With no app id, every stored token counts.
   */
  setAppId(appId: string | undefined): void {
    this.appId = appId || undefined;
  }

  /** The stored value, or undefined when it is a JWT issued for another app than this one. */
  private ownToken(value: string | null): string | undefined {
    if (!value) return undefined;
    if (!this.appId) return value;
    let aud: unknown;
    try {
      aud = parseToken(value).aud;
    } catch {
      // Not a JWT: no audience to check.
      return value;
    }
    // A token with no audience names no other app.
    if (aud === undefined) return value;
    const audience = Array.isArray(aud) ? aud : [aud];
    return audience.includes(this.appId) ? value : undefined;
  }

  /**
   * The value under `key`, the prefixed form of `name`. Earlier versions stored it under the
   * unprefixed `name`: such a value is moved to `key` on first read.
   */
  private readPrefixed(key: string, name: string): string | undefined {
    const value = this.storage.getItem(key);
    if (value || key === name) return value ?? undefined;
    const unprefixed = this.storage.getItem(name);
    if (!unprefixed) return undefined;
    this.storage.setItem(key, unprefixed);
    this.storage.removeItem(name);
    return unprefixed;
  }

  /** Removes `key` and the unprefixed `name`, so an old value is not read again. */
  private removePrefixed(key: string, name: string): void {
    this.storage.removeItem(key);
    if (key !== name) this.storage.removeItem(name);
  }

  private readToken(key: string): string | undefined {
    return this.ownToken(this.storage.getItem(key));
  }

  /** The keys a stored token lives in: the JSON tokens and the cookie-mode ID token. */
  private tokenValueKeys(): string[] {
    return [
      this.getKeyForTokenType(TokenType.access_token),
      this.getKeyForTokenType(TokenType.refresh_token),
      this.getKeyForTokenType(TokenType.id_token),
      this.ID_TOKEN_KEY,
    ];
  }

  /** Whether `key` holds a token issued for another app: this instance leaves it in place. */
  private holdsOtherAppToken(key: string): boolean {
    if (!this.appId) return false;
    const value = this.storage.getItem(key);
    return !!value && this.ownToken(value) === undefined;
  }

  /**
   * Whether the stored session is only another app's: some key holds another app's token and none
   * holds this app's. The keys every session shares (scopes, delivery mode, CSRF token) are then
   * that app's, and this instance's clearing leaves them in place.
   */
  holdsOnlyOtherAppSession(): boolean {
    if (!this.appId) return false;
    const keys = this.tokenValueKeys();
    return keys.some((key) => this.holdsOtherAppToken(key)) && !keys.some((key) => !!this.readToken(key));
  }

  /** Removes the token in `key` unless it is another app's. */
  private removeOwnToken(key: string): void {
    if (!this.holdsOtherAppToken(key)) this.storage.removeItem(key);
  }

  /**
   * Save tokens to storage with conditional logic based on delivery mode
   * In cookie/BFF mode: ONLY save ID token (not access/refresh tokens)
   * In JSON mode: save all tokens (existing behavior)
   */
  saveTokens(tokens: Tokens, deliveryMode?: TokenDeliveryMode): void {
    const { id_token, access_token, refresh_token, scopes } = tokens;

    if (deliveryMode === TokenDeliveryMode.Cookie || deliveryMode === TokenDeliveryMode.BFF) {
      // Cookie/BFF mode: ONLY save ID token (access/refresh in HttpOnly cookies)
      if (id_token) {
        this.storage.setItem(this.ID_TOKEN_KEY, id_token);
      }
      // Do NOT save access_token or refresh_token in localStorage
    } else {
      // JSON mode: save all tokens (existing behavior)
      if (id_token) this.storage.setItem(this.getKeyForTokenType(TokenType.id_token), id_token);
      if (access_token) this.storage.setItem(this.getKeyForTokenType(TokenType.access_token), access_token);
      if (refresh_token) this.storage.setItem(this.getKeyForTokenType(TokenType.refresh_token), refresh_token);
      if (scopes) this.storage.setItem(this.scopes, scopes.join(','));
    }
  }

  getToken(tokenType: TokenType): string | undefined {
    return this.readToken(this.getKeyForTokenType(tokenType));
  }

  /**
   * Get tokens from storage with conditional logic based on delivery mode
   * In cookie/BFF mode: return ID token only (access/refresh in HttpOnly cookies)
   * In JSON mode: return all stored tokens (existing behavior)
   */
  getTokens(): Tokens | undefined {
    const mode = this.getDeliveryMode();

    if (mode === TokenDeliveryMode.Cookie || mode === TokenDeliveryMode.BFF) {
      // Cookie/BFF mode: return ID token only (access/refresh in HttpOnly cookies)
      const idToken = this.readToken(this.ID_TOKEN_KEY);
      if (!idToken) return undefined;
      return {
        id_token: idToken,
        // access_token and refresh_token are in HttpOnly cookies, not localStorage
      };
    }

    // JSON mode: return all stored tokens (existing behavior)
    const access = this.readToken(this.getKeyForTokenType(TokenType.access_token));
    if (!access) return undefined;
    return {
      access_token: access,
      id_token: this.readToken(this.getKeyForTokenType(TokenType.id_token)),
      refresh_token: this.readToken(this.getKeyForTokenType(TokenType.refresh_token)),
      scopes: this.getScopes(),
    };
  }

  getScopes(): string[] | undefined {
    return this.readPrefixed(this.scopes, SCOPES_KEY)?.split(',');
  }

  /**
   * Check if JSON mode tokens exist in storage (ignores delivery mode)
   * Used to detect stale state where delivery_mode is set but JSON tokens exist
   */
  hasJsonModeTokens(): boolean {
    return !!this.readToken(this.getKeyForTokenType(TokenType.access_token));
  }

  /**
   * Check if cookie mode ID token exists in storage
   * Used to detect legitimate cookie/BFF mode sessions
   */
  hasCookieModeIdToken(): boolean {
    return !!this.readToken(this.ID_TOKEN_KEY);
  }

  deleteToken(tokenType: TokenType): void {
    const key = this.getKeyForTokenType(tokenType);
    this.storage.removeItem(key);
  }

  /**
   * Clears this app's stored session, key by key: a key holding another app's token stays. The
   * keys every session shares (scopes, delivery mode, CSRF token) stay only when the stored session
   * is another app's alone, and the hosted sign-in record only when another app wrote it.
   */
  deleteTokens(): void {
    // Decided before anything is removed: afterwards none of this app's tokens is left to tell.
    const keepShared = this.holdsOnlyOtherAppSession();

    // Clear JSON mode tokens and the cookie mode ID token
    for (const key of this.tokenValueKeys()) this.removeOwnToken(key);

    if (!keepShared) {
      // Clear scopes, delivery mode and CSRF token to ensure clean state for next session
      this.removePrefixed(this.scopes, SCOPES_KEY);
      this.clearDeliveryMode();
      this.removeCsrfToken();
    }
    if (!this.appId || this.getHostedSignIn() !== undefined || !this.storage.getItem(this.hostedSignInKey())) {
      this.storage.removeItem(this.hostedSignInKey());
    }
  }

  /**
   * Records that the stored session came from the hosted login, with the address it landed on.
   * The hosted login keeps a session of its own, which a sign-out then ends too.
   */
  setHostedSignIn(returnUrl: string): void {
    this.storage.setItem(this.hostedSignInKey(), JSON.stringify({ appId: this.appId ?? '', returnUrl }));
  }

  /**
   * The address the hosted sign-in of the stored session landed on, or undefined. A record another
   * app wrote on the same origin does not count.
   */
  getHostedSignIn(): string | undefined {
    try {
      const record = JSON.parse(this.storage.getItem(this.hostedSignInKey()) ?? '') as { appId?: unknown; returnUrl?: unknown };
      if (record.appId !== (this.appId ?? '') || typeof record.returnUrl !== 'string') return undefined;
      return record.returnUrl || undefined;
    } catch {
      return undefined;
    }
  }

  private hostedSignInKey(): string {
    return `${this.keyStoragePrefix}${this.STORAGE_PREFIX}hosted_sign_in`;
  }

  getDeviceId(): string | undefined {
    return this.readPrefixed(this.deviceId, DEVICE_ID_KEY);
  }

  setDeviceId(deviceId: string): void {
    this.storage.setItem(this.deviceId, deviceId);
  }

  deleteDeviceId(): void {
    this.removePrefixed(this.deviceId, DEVICE_ID_KEY);
  }

  setInvitationToken(token: string): void {
    this.storage.setItem(this.invitationToken, token);
  }

  getInvitationToken(): string | undefined {
    return this.readPrefixed(this.invitationToken, INVITATION_TOKEN_KEY);
  }

  deleteInvitationToken(): void {
    this.removePrefixed(this.invitationToken, INVITATION_TOKEN_KEY);
  }

  setPreviousRedirectUrl(url: string): void {
    this.storage.setItem(this.previousRedirectUrl, url);
  }

  getPreviousRedirectUrl(): string | undefined {
    return this.readPrefixed(this.previousRedirectUrl, PREVIOUS_REDIRECT_URL_KEY);
  }

  deletePreviousRedirectUrl(): void {
    this.removePrefixed(this.previousRedirectUrl, PREVIOUS_REDIRECT_URL_KEY);
  }

  // Delivery mode storage methods

  /**
   * Set the token delivery mode in storage
   */
  setDeliveryMode(mode: TokenDeliveryMode): void {
    try {
      this.storage.setItem(this.DELIVERY_MODE_KEY, mode);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Get the token delivery mode from storage
   */
  getDeliveryMode(): TokenDeliveryMode | undefined {
    try {
      const mode = this.storage.getItem(this.DELIVERY_MODE_KEY);
      if (mode && Object.values(TokenDeliveryMode).includes(mode as TokenDeliveryMode)) {
        return mode as TokenDeliveryMode;
      }
    } catch (_error) {
      // Silently ignore storage errors
    }
    return undefined;
  }

  /**
   * Clear the delivery mode from storage
   */
  clearDeliveryMode(): void {
    try {
      this.storage.removeItem(this.DELIVERY_MODE_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  // ID token storage methods (for cookie mode)

  /**
   * Get the ID token from storage (cookie mode)
   */
  getIdToken(): string | undefined {
    try {
      return this.readToken(this.ID_TOKEN_KEY);
    } catch (_error) {
      // Silently ignore storage errors
      return undefined;
    }
  }

  /**
   * Set the ID token in storage (cookie mode)
   */
  setIdToken(token: string): void {
    try {
      this.storage.setItem(this.ID_TOKEN_KEY, token);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Clear the ID token from storage
   */
  clearIdToken(): void {
    try {
      this.removeOwnToken(this.ID_TOKEN_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  // CSRF token storage methods

  /**
   * Get the CSRF token from storage
   */
  getCsrfToken(): string | undefined {
    try {
      return this.storage.getItem(this.CSRF_TOKEN_KEY) ?? undefined;
    } catch (_error) {
      // Silently ignore storage errors
      return undefined;
    }
  }

  /**
   * Set the CSRF token in storage
   */
  setCsrfToken(token: string): void {
    try {
      this.storage.setItem(this.CSRF_TOKEN_KEY, token);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Clear the CSRF token from storage
   */
  clearCsrfToken(): void {
    // Another app's session alone in storage: the CSRF token is that app's.
    if (this.holdsOnlyOtherAppSession()) return;
    this.removeCsrfToken();
  }

  private removeCsrfToken(): void {
    try {
      this.storage.removeItem(this.CSRF_TOKEN_KEY);
    } catch (_error) {
      // Silently ignore storage errors
    }
  }

  /**
   * Every storage key the token session lives in (JSON tokens, scopes, the cookie-mode ID token,
   * CSRF token and delivery mode). The refresh coordinator filters `storage` events by it, so
   * writes to unrelated keys never wake the refresh path.
   */
  tokenKeys(): string[] {
    return [
      this.getKeyForTokenType(TokenType.id_token),
      this.getKeyForTokenType(TokenType.access_token),
      this.getKeyForTokenType(TokenType.refresh_token),
      this.scopes,
      this.ID_TOKEN_KEY,
      this.CSRF_TOKEN_KEY,
      this.DELIVERY_MODE_KEY,
    ];
  }

  private getKeyForTokenType(tokenType: TokenType): string {
    return `${this.keyStoragePrefix}${tokenType}`;
  }
}
