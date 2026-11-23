import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/browser';
import type { AxiosRequestConfig } from 'axios';
import { withAntiBot } from '../anti-bot/markers';
import type { AntiBotOperation } from '../anti-bot/types';
import { AGENT_TOOL_HEADER_KEY, APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY } from '../constants';

import { DeviceService } from '../device';
import { StorageManager } from '../storage';
import { markUpgradeTransaction } from '../upgrade/markers';

import { type AxiosAntiBotHandler, AxiosClient } from './axios-client';
import {
  type AntiBotChallenge,
  OS,
  PassflowAdminEndpointPaths,
  PassflowAuthOptions,
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEmailCodePayload,
  PassflowEndpointPaths,
  PassflowError,
  PassflowFederatedStartBody,
  PassflowFederatedStartResponse,
  PassflowLogoutResponse,
  PassflowPasskeyAuthenticatePayload,
  PassflowPasskeyAuthenticateStartExtendedPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyRegisterPayload,
  PassflowPasskeyRegisterStartExtendedPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasskeyStart,
  PassflowPasswordlessApprovalDecidePayload,
  PassflowPasswordlessApprovalDecideResponse,
  PassflowPasswordlessApprovalInfoPayload,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInExtendedPayload,
  PassflowPasswordlessSignInPayload,
  PassflowPasswordlessStatusPayload,
  PassflowPasswordlessStatusResponse,
  PassflowResponseError,
  PassflowSendPasswordResetEmailPayload,
  PassflowSessionValidationResponse,
  PassflowSignInExtendedPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidatePayload,
  PassflowValidationResponse,
  PasswordlessApprovalInfo,
  UpgradeRefreshField,
} from './model';

/**
 * Request config for the calls that end a sign-in.
 *
 * They go with credentials so the browser sends the trusted-device cookie
 * (`passflow_trusted_device_<appID>`) the server reads to skip the second
 * factor, and so a cross-origin response can set it. Only the per-request
 * flag: the Authorization and CSRF handling stay as the interceptor has them.
 */
const SIGN_IN_REQUEST_CONFIG: AxiosRequestConfig = { withCredentials: true };

/** One status poll may take this long, so a stalled request cannot hold up the next one. */
const PASSWORDLESS_STATUS_TIMEOUT_MS = 15000;

/** The device verification page's CSRF header, required by every `/oidc/device/*` POST. */
const DEVICE_CSRF_HEADER_KEY = 'X-Passflow-CSRF';

const SIGN_IN_FAILED_MESSAGE = 'Sign-in failed. Start again.';
const TRY_AGAIN_LATER_MESSAGE = 'Something went wrong. Try again later.';

/**
 * The plain error of a failed call whose body holds a secret. The rejections the axios client
 * passes on raw (a POST 429, a cancel, a timeout) hold that body in `config.data`, so only the
 * fields the server wrote are read here: never axios `config`, `request` or the original error.
 * A network failure already arrives as a `PassflowError` whose cause carries no config.
 */
const toPlainError = (error: unknown, path: PassflowEndpointPaths, id: string, message: string): PassflowError => {
  if (error instanceof PassflowError) return error;
  const body = (error as { response?: { data?: Partial<PassflowResponseError> } } | undefined)?.response?.data?.error;
  return new PassflowError({
    id: typeof body?.id === 'string' ? body.id : id,
    message: typeof body?.message === 'string' ? body.message : message,
    status: typeof body?.status === 'number' ? body.status : 0,
    location: path,
    time: new Date().toISOString(),
  });
};

/**
 * The config of one sign-in call: `base`, the anti-bot mark when the call is covered, and the
 * agent-tool header when the caller asked for it. With neither, it is `base` itself, so an
 * uncovered call and a call without options send exactly what they sent before.
 */
const callConfig = (
  base: AxiosRequestConfig | undefined,
  operation: AntiBotOperation | undefined,
  identifier: string | undefined,
  options?: PassflowAuthOptions,
): AxiosRequestConfig | undefined => {
  if (!operation && !options?.agentTool) return base;
  return {
    ...base,
    ...(operation ? withAntiBot(operation, identifier) : {}),
    ...(options?.agentTool ? { headers: { ...base?.headers, [AGENT_TOOL_HEADER_KEY]: '1' } } : {}),
  };
};

export class AuthAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  /** Installs (or clears) the handler that produces the anti-bot value of covered calls. */
  setAntiBotHandler(handler: AxiosAntiBotHandler | undefined): void {
    this.axiosClient.setAntiBotHandler(handler);
  }

  /**
   * A built-in anti-bot challenge for this app. `identifier` is used by the server for difficulty
   * only. Rejects only with a `PassflowError`.
   */
  async antiBotChallenge(payload: { identifier?: string }): Promise<AntiBotChallenge> {
    try {
      return await this.axiosClient.post<AntiBotChallenge, { identifier?: string }>(
        PassflowEndpointPaths.antiBotChallenge,
        payload,
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.antiBotChallenge, 'error.anti_bot.challenge', TRY_AGAIN_LATER_MESSAGE);
    }
  }

  /**
   * A built-in anti-bot challenge for the device verification page, for the app of `user_code`.
   * Same-origin only, with the page's CSRF token. Rejects only with a `PassflowError`.
   */
  async deviceAntiBotChallenge(
    payload: { user_code: string; identifier?: string },
    csrfToken: string,
  ): Promise<AntiBotChallenge> {
    try {
      return await this.axiosClient.post<AntiBotChallenge, { user_code: string; identifier?: string }>(
        PassflowEndpointPaths.deviceAntiBotChallenge,
        payload,
        { headers: { [DEVICE_CSRF_HEADER_KEY]: csrfToken } },
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.deviceAntiBotChallenge,
        'error.anti_bot.challenge',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Starts a federated sign-in with a POST, which can carry the anti-bot and agent-tool headers,
   * and answers the provider's URL to navigate to. Sent with credentials, so the browser keeps the
   * challenge cookie the answer sets.
   */
  federatedStart(
    provider: string,
    body: PassflowFederatedStartBody,
    options?: PassflowAuthOptions,
  ): Promise<PassflowFederatedStartResponse> {
    return this.axiosClient.post<PassflowFederatedStartResponse, PassflowFederatedStartBody>(
      `${PassflowEndpointPaths.signInWithProvider}${provider}`,
      body,
      callConfig(SIGN_IN_REQUEST_CONFIG, 'federated.start', undefined, options),
    );
  }

  /**
   * Refreshes the session, optionally committing an assurance upgrade.
   *
   * `upgrade` carries `{type, assertion}` — the proof the user just produced.
   * The server scores the new `acr` from the durable session record plus the
   * verified factor and rotates the tokens, so this one endpoint is both the
   * refresh and the elevation.
   *
   * When `upgrade` is present the request is MARKED as part of the upgrade
   * transaction. The server answers a wrong code, a spent challenge, a foreign
   * session and an exhausted budget with a bare 401 carrying no RFC 9470
   * vocabulary, which is indistinguishable from an expired session on the
   * response alone; the marker is what tells the response interceptor not to
   * invalidate the session over a mistyped digit.
   */
  refreshToken(
    refreshToken: string,
    scopes: string[],
    accessToken?: string,
    upgrade?: UpgradeRefreshField,
  ): Promise<PassflowAuthorizationResponse> {
    const payload = {
      access: accessToken,
      scopes,
      // Omitted entirely rather than sent as `null` when absent: the server
      // decodes non-strictly and an explicit null would be a value, not a gap.
      ...(upgrade ? { upgrade } : {}),
    };

    const config: AxiosRequestConfig = {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${refreshToken}`,
      },
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, typeof payload>(
      PassflowEndpointPaths.refresh,
      payload,
      upgrade ? markUpgradeTransaction(config) : config,
    );
  }

  signIn(
    payload: PassflowSignInPayload,
    deviceId: string,
    os: OS,
    options?: PassflowAuthOptions,
  ): Promise<PassflowAuthorizationResponse> {
    const defaultPayload: PassflowSignInExtendedPayload = {
      ...payload,
      device: deviceId,
      os,
    };
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowSignInExtendedPayload>(
      PassflowEndpointPaths.signin,
      defaultPayload,
      callConfig(SIGN_IN_REQUEST_CONFIG, 'sign-in', payload.email ?? payload.phone ?? payload.username, options),
    );
  }

  signUp(payload: PassflowSignUpPayload, options?: PassflowAuthOptions): Promise<PassflowAuthorizationResponse> {
    const { create_tenant, anonymous } = payload;
    const defaultPayload: PassflowSignUpPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      anonymous: anonymous ?? false,
    };
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowSignUpPayload>(
      PassflowEndpointPaths.signup,
      defaultPayload,
      callConfig(
        SIGN_IN_REQUEST_CONFIG,
        'sign-up',
        payload.user.email ?? payload.user.phone_number ?? payload.user.username,
        options,
      ),
    );
  }

  /**
   * Redeems the code a PKCE sign-in answered with for the tokens it stands for.
   *
   * Every exchange goes through here, so this is the one place that keeps the code and the
   * verifier out of its errors: it rejects only with a `PassflowError`.
   */
  async pkceExchange(code: string, verifier: string): Promise<PassflowAuthorizationResponse> {
    try {
      return await this.axiosClient.post<PassflowAuthorizationResponse, { authz_code: string; verifier: string }>(
        PassflowEndpointPaths.pkceExchange,
        { authz_code: code, verifier },
        SIGN_IN_REQUEST_CONFIG,
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.pkceExchange, 'error.pkce.exchange', SIGN_IN_FAILED_MESSAGE);
    }
  }

  /** Rejects only with a `PassflowError`, because its body can hold the poll secret. */
  async passwordlessSignIn(
    payload: PassflowPasswordlessSignInPayload,
    deviceId: string,
    os: OS,
    options?: PassflowAuthOptions,
  ): Promise<PassflowPasswordlessResponse> {
    const { create_tenant } = payload;
    const defaultPayload: PassflowPasswordlessSignInExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };
    try {
      return await this.axiosClient.post<PassflowPasswordlessResponse, PassflowPasswordlessSignInExtendedPayload>(
        PassflowEndpointPaths.passwordless,
        defaultPayload,
        callConfig(undefined, 'passwordless.start', payload.email ?? payload.phone, options),
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.passwordless, 'error.passwordless.start', TRY_AGAIN_LATER_MESSAGE);
    }
  }

  /** Rejects only with a `PassflowError`, because its body holds the OTP. */
  async passwordlessSignInComplete(
    payload: PassflowPasswordlessSignInCompletePayload,
    options?: PassflowAuthOptions,
  ): Promise<PassflowValidationResponse> {
    try {
      return await this.axiosClient.post<PassflowValidationResponse, PassflowPasswordlessSignInCompletePayload>(
        PassflowEndpointPaths.passwordlessComplete,
        payload,
        callConfig(SIGN_IN_REQUEST_CONFIG, undefined, undefined, options),
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessComplete,
        'error.passwordless.complete',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Polls a magic-link sign-in waiting for approval from another device. Sent with credentials:
   * the trusted-device cookie is read when an approved row answers with its code. It rejects only
   * with a `PassflowError`, because its body holds the poll secret.
   */
  async passwordlessStatus(
    payload: PassflowPasswordlessStatusPayload,
    options?: { signal?: AbortSignal },
  ): Promise<PassflowPasswordlessStatusResponse> {
    try {
      return await this.axiosClient.post<PassflowPasswordlessStatusResponse, PassflowPasswordlessStatusPayload>(
        PassflowEndpointPaths.passwordlessStatus,
        payload,
        { ...SIGN_IN_REQUEST_CONFIG, timeout: PASSWORDLESS_STATUS_TIMEOUT_MS, signal: options?.signal },
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.passwordlessStatus, 'error.passwordless.status', SIGN_IN_FAILED_MESSAGE);
    }
  }

  /** Asks the server whether this app may redirect to `url`, and for the address to use. */
  async checkRedirectUrl(url: string): Promise<string> {
    try {
      const answer = await this.axiosClient.post<{ redirect_url: string }, { redirect_url: string }>(
        PassflowEndpointPaths.redirectCheck,
        { redirect_url: url },
      );
      return answer.redirect_url;
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.redirectCheck, 'error.redirect.check', TRY_AGAIN_LATER_MESSAGE);
    }
  }

  /** Reads what the approving device shows. It changes nothing on the server. */
  async passwordlessApprovalInfo(payload: PassflowPasswordlessApprovalInfoPayload): Promise<PasswordlessApprovalInfo> {
    try {
      return await this.axiosClient.post<PasswordlessApprovalInfo, PassflowPasswordlessApprovalInfoPayload>(
        PassflowEndpointPaths.passwordlessApprovalInfo,
        payload,
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessApprovalInfo,
        'error.passwordless.approval',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Approves or denies a waiting sign-in from the device that opened the link. It rejects only with
   * a `PassflowError`, because its body holds the OTP and the match code.
   */
  async passwordlessApprovalDecide(
    payload: PassflowPasswordlessApprovalDecidePayload,
  ): Promise<PassflowPasswordlessApprovalDecideResponse> {
    try {
      return await this.axiosClient.post<PassflowPasswordlessApprovalDecideResponse, PassflowPasswordlessApprovalDecidePayload>(
        PassflowEndpointPaths.passwordlessApprovalDecide,
        payload,
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessApprovalDecide,
        'error.passwordless.approval',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Proves an emailed code for a sign-up, sign-in or password change that answered with
   * `email_verification_required`. Only `{challenge_id, otp}` is sent: the server reads the
   * device from the `X-Passflow-DeviceId` header. Sent with credentials, as every call that
   * ends a sign-in is.
   */
  validateEmailCode(payload: PassflowEmailCodePayload): Promise<PassflowAuthorizationResponse> {
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowEmailCodePayload>(
      PassflowEndpointPaths.passkeyValidate,
      { challenge_id: payload.challenge_id, otp: payload.otp },
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  logOut(deviceId?: string, refreshToken?: string, isAdmin = false): Promise<PassflowLogoutResponse> {
    const payload = !isAdmin ? { refresh_token: refreshToken, device: deviceId } : undefined;
    const endpoint = isAdmin ? PassflowAdminEndpointPaths.logout : PassflowEndpointPaths.logout;

    return this.axiosClient.post<PassflowLogoutResponse, typeof payload>(endpoint, payload);
  }

  validateSession(): Promise<PassflowSessionValidationResponse> {
    return this.axiosClient.get<PassflowSessionValidationResponse>(PassflowEndpointPaths.validateSession);
  }

  sendPasswordResetEmail(
    payload: PassflowSendPasswordResetEmailPayload,
    options?: PassflowAuthOptions,
  ): Promise<PassflowSuccessResponse> {
    return this.axiosClient.post<PassflowSuccessResponse, typeof payload>(
      PassflowEndpointPaths.sendPasswordResetEmail,
      payload,
      callConfig(undefined, 'password-reset.send', payload.email ?? payload.phone ?? payload.username, options),
    );
  }

  resetPassword(
    newPassword: string,
    scopes: string[],
    resetToken?: string,
    codeChallenge?: string,
  ): Promise<PassflowAuthorizationResponse> {
    const payload = {
      password: newPassword,
      scopes,
      ...(codeChallenge ? { code_challenge: codeChallenge } : {}),
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, typeof payload>(PassflowEndpointPaths.resetPassword, payload, {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${resetToken}`,
        [APP_ID_HEADER_KEY]: undefined,
      },
    });
  }

  passkeyRegisterStart(
    payload: PassflowPasskeyRegisterStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
    options?: PassflowAuthOptions,
  ): Promise<PassflowPasskeyStart> {
    const { create_tenant } = payload;
    const defaultPayload: PassflowPasskeyRegisterStartExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };

    const endpoint = isAdmin ? PassflowAdminEndpointPaths.passkeyRegisterStart : PassflowEndpointPaths.passkeyRegisterStart;

    // The admin routes are not covered by the anti-bot check.
    return this.axiosClient.post<PassflowPasskeyStart, PassflowPasskeyRegisterStartExtendedPayload>(
      endpoint,
      defaultPayload,
      callConfig(undefined, isAdmin ? undefined : 'passkey.register', payload.passkey_username, options),
    );
  }

  passkeyRegisterComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
    options?: PassflowAuthOptions,
  ): Promise<PassflowAuthorizationResponse> {
    const payload: PassflowPasskeyRegisterPayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyRegisterComplete
      : PassflowEndpointPaths.passkeyRegisterComplete;

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyRegisterPayload>(
      endpoint,
      payload,
      callConfig(SIGN_IN_REQUEST_CONFIG, undefined, undefined, options),
    );
  }

  passkeyAuthenticateStart(
    payload: PassflowPasskeyAuthenticateStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
    options?: PassflowAuthOptions,
  ): Promise<PassflowPasskeyStart> {
    const defaultPayload: PassflowPasskeyAuthenticateStartExtendedPayload = {
      ...payload,
      user_id: payload.user_id ?? '',
      device: deviceId,
      os,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyAuthenticateStart
      : PassflowEndpointPaths.passkeyAuthenticateStart;

    return this.axiosClient.post<PassflowPasskeyStart, PassflowPasskeyAuthenticateStartExtendedPayload>(
      endpoint,
      defaultPayload,
      callConfig(undefined, isAdmin ? undefined : 'passkey.authenticate', undefined, options),
    );
  }

  passkeyAuthenticateComplete(
    passkeyData: AuthenticationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
    options?: PassflowAuthOptions,
  ): Promise<PassflowAuthorizationResponse> {
    const payload: PassflowPasskeyAuthenticatePayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyAuthenticateComplete
      : PassflowEndpointPaths.passkeyAuthenticateComplete;

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyAuthenticatePayload>(
      endpoint,
      payload,
      callConfig(SIGN_IN_REQUEST_CONFIG, undefined, undefined, options),
    );
  }

  passkeyValidate(
    otp: string,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
    appId?: string,
  ): Promise<PassflowValidationResponse> {
    const payload: PassflowValidatePayload = {
      otp,
      device: deviceId,
      challenge_id: challengeId,
    };

    let endpoint: PassflowEndpointPaths.passkeyValidate | PassflowAdminEndpointPaths.passkeyValidate =
      PassflowEndpointPaths.passkeyValidate;
    if (!appId && isAdmin) {
      endpoint = PassflowAdminEndpointPaths.passkeyValidate;
    }

    const headers = appId ? { [APP_ID_HEADER_KEY]: appId } : {};

    return this.axiosClient.post<PassflowValidationResponse, PassflowValidatePayload>(endpoint, payload, { headers });
  }
}
