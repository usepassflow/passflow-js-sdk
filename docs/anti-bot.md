# Bot mode and the anti-bot check

Each app has a bot mode, read from `GET /app/settings`:

- `bot_friendly` (and any server that does not report `bot_mode`): nothing changes. The SDK sends
  no challenge request, no extra header and no anti-bot event.
- `human_only`: every sign-in start must carry `X-Passflow-Anti-Bot`. The SDK adds it for the calls
  it sends. Its value is the answer to Passflow's built-in proof of work, or a token from the app's
  own provider (Turnstile, hCaptcha, reCAPTCHA).

`anti_bot.provider` in the settings says which. A `human_only` app with no `anti_bot` uses the
built-in check.

## Covered calls

The SDK adds the header to these requests, and only these:

| Method | Request |
|---|---|
| `signIn` | `POST /auth/login` |
| `signUp` | `POST /auth/register` |
| `passwordlessSignIn` | `POST /auth/passwordless/start` |
| `passkeyRegister` | `POST /auth/passkey/register/start` |
| `passkeyAuthenticate` | `POST /auth/passkey/authenticate/start` |
| `sendPasswordResetEmail` | `POST /auth/password/reset` |
| `federatedAuthWithPopup`, `federatedAuthWithRedirect` | `POST /auth/federated/start/{provider}` |

The value is produced inside the request, so each request gets its own. A second
`passwordlessSignIn` for "resend code" gets a new one. A value is accepted once.

The admin passkey routes (`/admin/auth/*`, used with no app id) are not covered.

## Built-in check

Before each covered request the SDK asks for a challenge, `POST /auth/anti-bot/challenge` with the
email, phone or username when the call has one (the server uses it for difficulty only). It finds
the number that answers the challenge with SHA-256 and sends the result.

The search runs in a Web Worker when you give the SDK the worker file. Serve
`@passflow/core/anti-bot-worker.js` from your own origin and pass its URL:

```typescript
const passflow = new Passflow({ appId, url, antiBotWorkerUrl: '/anti-bot-worker.js' });
```

With Vite you can import the URL: `import workerUrl from '@passflow/core/anti-bot-worker.js?url'`.
The file is a classic script, never a `blob:` URL, so a `script-src 'self'` policy allows it.
Without `antiBotWorkerUrl`, or where `Worker` does not exist, the search runs on the main thread.
A worker that fails to load is an error, not a reason to fall back.

When the server answers 403 `error.api.anti_bot.failed` (the challenge expired, or the server
changed its key), the SDK asks for a new challenge, solves it, and sends the request once more.
A second `failed` is surfaced.

## Your own provider

Give the SDK a function that resolves with the provider's token:

```typescript
passflow.setAntiBotTokenProvider(({ action, operation }) => getTurnstileToken({ action }));
```

`action` is always `'passflow_auth'`; a reCAPTCHA score key must be executed with it. `operation`
names the call (`'sign-in'`, `'passwordless.start'`, ...). The token is sent as it is. A `failed`
answer is surfaced at once, with no second call to the provider.

On a `human_only` app with a provider and no function set, a covered call rejects with
`error.anti_bot.provider_missing` and sends nothing. A function that rejects or resolves `''`
gives `error.anti_bot.provider_failed`.

## Events

`PassflowEvent.AntiBotSolving` and `PassflowEvent.AntiBotSolved` carry `{ operation, provider }`.
They fire once per value produced, so a resend fires a second pair. A failure fires `AntiBotSolving`
and no `AntiBotSolved`, then the covered call's usual `Error` event with its own `operation` and
`code` set to the error id.

## Errors

| Id | When |
|---|---|
| `error.api.anti_bot.required` (403) | The request had no value. Not resent. |
| `error.api.anti_bot.failed` (403) | Wrong, expired or reused. The built-in check is resent once. |
| `error.api.anti_bot.unavailable` (503) | The server cannot check now. Not resent; try again later. |
| `error.anti_bot.provider_missing` | Own provider, no `setAntiBotTokenProvider()`. |
| `error.anti_bot.provider_failed` | The provider function rejected or resolved `''`. |
| `error.anti_bot.solve_failed` | No Web Crypto (plain http), a worker error, or no answer found. |

## Federated sign-in

A header cannot ride a navigation, so on a `human_only` app the federated start is a POST. The SDK
then goes to the `auth_url` it answers with. The popup opens blank at once, inside the click, and
follows the URL when the start answers. A platform adapter can do the same with
`openPendingAuthUrl`; one without it gets `openAuthUrl(auth_url)` once the URL is known.

`createFederatedAuthUrl` still builds the GET start, which a `human_only` app refuses.

The start answer sets a `SameSite=Lax` cookie the provider's callback needs. A browser keeps it only
when the page and the Passflow server are on the same site, such as the hosted login page or a
custom domain. An app on another site that starts federated sign-in itself on a `human_only` app
can fail at the callback.

## Agent tools

`{ agentTool: true }` as the last argument of a sign-in method adds `X-Passflow-Agent-Tool: 1`, on
which the server refuses a device parent. Only agent tool actions set it. With it, a federated
start is always a POST.

```typescript
await passflow.signIn({ email, password }, { agentTool: true });
```

## Requests the SDK does not send

`POST /auth/session/exchange`, `/oidc/device/authenticate` and `/oidc/device/passkey/start` need the
header too. Ask the SDK for a value and send it yourself:

```typescript
const value = await passflow.antiBotToken({ operation: 'session.exchange' });
const headers = value ? { 'X-Passflow-Anti-Bot': value } : {};
```

`undefined` means the app is not `human_only`: send no header. The device page has no app id. It
passes the `bot_mode` and `anti_bot` from `GET /oidc/device/info`, and the user code with the page's
CSRF token. The challenge then comes from `POST /oidc/device/anti-bot/challenge`, which is
same-origin only, so that page's `Passflow` needs `url` set to its own origin:

```typescript
const value = await passflow.antiBotToken({
  operation: 'device.authenticate',
  identifier: email,
  settings: { bot_mode: info.bot_mode, anti_bot: info.anti_bot },
  device: { userCode, csrfToken },
});
```

A device passkey sign-in needs two values, one for each request.
