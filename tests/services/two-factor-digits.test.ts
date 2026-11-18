/**
 * The TOTP digit count: learned from a server answer, held for one sign-in only, and checked
 * locally only when it is known.
 *
 * Requests run through the real AxiosClient and TwoFactorService and stop at a capturing adapter.
 */
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { describe, expect, test } from 'vitest';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { TwoFactorService } from '../../lib/services/two-factor-service';
import { StorageManager } from '../../lib/storage';
import { PassflowStore } from '../../lib/store';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';

const TFA_TOKEN = 'tfa.jwt.token';

const setup = (enrollment: unknown = { enrollment: 'verify' }) => {
  localStorage.clear();
  sessionStorage.clear();
  const api = new TwoFactorApiClient(TEST_CONFIG, new StorageManager({ prefix: '' }));
  const requests: InternalAxiosRequestConfig[] = [];
  const adapter: AxiosAdapter = async (config) => {
    requests.push(config);
    const data = config.url === '/auth/2fa/enrollment' ? enrollment : { ...VALID_TOKENS };
    return { data, status: 200, statusText: '', headers: {}, config };
  };
  // The axios instance is private; reaching it is the point of this harness.
  (api as unknown as { axiosClient: { instance: { defaults: { adapter: unknown } } } }).axiosClient.instance.defaults.adapter =
    adapter;
  const service = new TwoFactorService(api, new PassflowStore());
  service.setPartialAuthState('', '', TFA_TOKEN);
  const verifyCalls = () => requests.filter((config) => config.url === '/auth/2fa/verify');
  return { service, verifyCalls };
};

// REGRESSION: the digit count is known only from a server answer and lasts one sign-in
describe('TOTP digit count', () => {
  test('with no count known, an 8-digit code reaches the server', async () => {
    const { service, verifyCalls } = setup();

    await service.verify('12345678');

    expect(verifyCalls()).toHaveLength(1);
    expect(JSON.parse(verifyCalls()[0]?.data as string)).toEqual({ code: '12345678' });
  });

  test('a count learned on an abandoned sign-in does not carry over to the next one', async () => {
    const { service, verifyCalls } = setup({ enrollment: 'verify', totp_digits: 8, totp_period: 30 });
    await service.getEnrollment();
    expect(service.getTotpDigits()).toBe(8);

    // The user goes back and signs in again: a new second-factor step starts, nothing was cleared.
    service.setPartialAuthState('', '', 'another.tfa.token');
    expect(service.getTotpDigits()).toBe(6);
    await service.verify('123456');

    expect(verifyCalls()).toHaveLength(1);
    expect(JSON.parse(verifyCalls()[0]?.data as string)).toEqual({ code: '123456' });
  });

  test('a count learned on one sign-in is gone once it is cleared', async () => {
    const { service, verifyCalls } = setup({ enrollment: 'verify', totp_digits: 8, totp_period: 30 });
    await service.getEnrollment();
    expect(service.getTotpDigits()).toBe(8);

    service.clearPartialAuthState();
    expect(service.getTotpDigits()).toBe(6);

    service.setPartialAuthState('', '', TFA_TOKEN);
    await service.verify('123456');

    expect(verifyCalls()).toHaveLength(1);
    expect(JSON.parse(verifyCalls()[0]?.data as string)).toEqual({ code: '123456' });
  });

  test('with 8 known, a 6-digit code is refused before any request', async () => {
    const { service, verifyCalls } = setup({ enrollment: 'verify', totp_digits: 8, totp_period: 30 });
    await service.getEnrollment();

    await expect(service.verify('123456')).rejects.toThrow('Code must be exactly 8 digits.');
    expect(verifyCalls()).toHaveLength(0);
  });

  test('with no count known, a 7-digit code is refused before any request', async () => {
    const { service, verifyCalls } = setup();

    await expect(service.verify('1234567')).rejects.toThrow('Code must be 6 or 8 digits.');
    expect(verifyCalls()).toHaveLength(0);
  });
});
