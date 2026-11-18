/**
 * The errors the SDK rejects with: their names, and the forced password change mapping.
 *
 * Real AxiosClient over a real StorageManager; only the HTTP adapter is stubbed.
 */
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { beforeEach, describe, expect, test } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import { PASSWORD_CHANGE_REQUIRED_ERROR_ID, PassflowError, PassflowPasswordChangeRequiredError } from '../../lib/index';
import { PassflowRefreshError, RefreshErrorId } from '../../lib/refresh/errors';
import { StorageManager } from '../../lib/storage';
import { createMockPlatform } from '../helpers/mock-platform';

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;

const respond =
  (status: number, data: unknown): Adapter =>
  (config) =>
    Promise.reject(
      new AxiosError(
        `Request failed with status code ${status}`,
        'ERR_BAD_REQUEST',
        config,
        { sent: true },
        {
          data,
          status,
          statusText: String(status),
          headers: {},
          config,
        },
      ),
    );

const outcomeOf = (promise: Promise<unknown>) =>
  promise.then(
    () => {
      throw new Error('call must reject, not resolve');
    },
    (error: unknown) => error,
  );

// REGRESSION: PassflowError carries its own name; subclasses keep theirs
describe('error names', () => {
  test('PassflowError is named PassflowError', () => {
    const error = new PassflowError({ id: 'error.x', message: 'x', status: 400, location: 'l', time: 't' });

    expect(error.name).toBe('PassflowError');
  });

  test('PassflowRefreshError keeps its own name', () => {
    expect(new PassflowRefreshError(RefreshErrorId.signedOut).name).toBe('PassflowRefreshError');
  });
});

// REGRESSION: a forced password change rejects with its own typed error
describe('a 403 asking for a password change', () => {
  let client: AxiosClient;
  let sent: InternalAxiosRequestConfig[];

  beforeEach(() => {
    localStorage.clear();
    client = new AxiosClient(
      { url: 'https://api.example.com', appId: 'app', platform: createMockPlatform() },
      new StorageManager({ prefix: '' }),
    );
    sent = [];
    (client as unknown as { instance: { defaults: { adapter: Adapter } } }).instance.defaults.adapter = (config) => {
      sent.push(config);
      return respond(403, {
        error: {
          id: 'error.api.password.change.required',
          message: 'You must change your password',
          status: 403,
          time: '2026-11-18T00:00:00Z',
        },
      })(config);
    };
  });

  test('the id is exported from the package entry', () => {
    expect(PASSWORD_CHANGE_REQUIRED_ERROR_ID).toBe('error.api.password.change.required');
  });

  test('rejects with PassflowPasswordChangeRequiredError, a PassflowError with the id and the status', async () => {
    const error = await outcomeOf(client.post('/auth/login', { email: 'a@example.com', password: 'pw' }));

    expect(error).toBeInstanceOf(PassflowPasswordChangeRequiredError);
    expect(error).toBeInstanceOf(PassflowError);
    expect(error).toMatchObject({
      id: PASSWORD_CHANGE_REQUIRED_ERROR_ID,
      status: 403,
      message: 'You must change your password',
    });
    expect(sent).toHaveLength(1);
  });
});
