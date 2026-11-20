// REGRESSION: device id is read or minted at the first request, never at construction; its storage key honours keyStoragePrefix.

/**
 * The device id a Passflow instance sends. A real `Passflow` over a real `StorageManager` and a
 * fake storage; only axios's HTTP adapter is stubbed, so every request the SDK sends is recorded
 * with the headers it carries.
 */

import axios, { type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, type MockInstance, test, vi } from 'vitest';
import { DEVICE_ID_HEADER_KEY } from '../../lib/constants';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { createMockPlatform } from '../helpers/mock-platform';
import { FakeStorage } from '../storage/fake-storage';

const URL = 'https://api.example.com';
const APP_ID = 'app-1';
const LEGACY_KEY = 'passflowDeviceId';
const PREFIXED_KEY = 'myapp_passflowDeviceId';

describe('device id', () => {
  let storage: FakeStorage;
  let sent: InternalAxiosRequestConfig[];
  let randomUUID: MockInstance<() => string>;
  let originalAdapter: typeof axios.defaults.adapter;

  const recordingAdapter: AxiosAdapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    sent.push(config);
    return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
  };

  const build = (keyStoragePrefix?: string) =>
    new Passflow({
      url: URL,
      appId: APP_ID,
      refreshCoordination: 'none',
      platform: createMockPlatform({ storage }),
      ...(keyStoragePrefix ? { keyStoragePrefix } : {}),
    });

  const deviceHeader = (config: InternalAxiosRequestConfig) => config.headers.get(DEVICE_ID_HEADER_KEY);

  beforeEach(() => {
    storage = new FakeStorage();
    sent = [];
    originalAdapter = axios.defaults.adapter;
    // Every client axios.create()s from the defaults, so the stub must be in place before construction.
    axios.defaults.adapter = recordingAdapter;
    randomUUID = vi.spyOn(globalThis.crypto, 'randomUUID');
  });

  afterEach(() => {
    axios.defaults.adapter = originalAdapter;
    randomUUID.mockRestore();
  });

  describe('Passflow construction', () => {
    test('constructing with empty storage draws no randomness and stores no device id', () => {
      const passflow = build();

      expect(passflow).toBeInstanceOf(Passflow);
      expect(randomUUID).not.toHaveBeenCalled();
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
      expect([...storage.data.keys()].filter((key) => key.includes('DeviceId'))).toEqual([]);
    });
  });

  describe('first request', () => {
    test('the first request carries a device id, which is minted then and persisted', async () => {
      const passflow = build();
      const storageManager = new StorageManager({ storage });
      expect(storageManager.getDeviceId()).toBeUndefined();

      await passflow.getSettingsAll();

      expect(sent).toHaveLength(1);
      const deviceId = deviceHeader(sent[0]);
      expect(typeof deviceId).toBe('string');
      expect(deviceId).not.toBe('');
      expect(storageManager.getDeviceId()).toBe(deviceId);
    });

    test('two API clients of one Passflow send the same device id, minted once', async () => {
      const passflow = build();

      await passflow.getSettingsAll();
      await passflow.getAppSettings();

      expect(sent).toHaveLength(2);
      const first = deviceHeader(sent[0]);
      expect(first).toBeTruthy();
      expect(deviceHeader(sent[1])).toBe(first);
      expect(randomUUID).toHaveBeenCalledTimes(1);
    });

    test('with keyStoragePrefix and a legacy stored id, the request sends the legacy id and keeps it under the prefixed key', async () => {
      storage.setItem(LEGACY_KEY, 'legacy-id');
      const passflow = build('myapp');

      await passflow.getSettingsAll();

      expect(sent).toHaveLength(1);
      expect(deviceHeader(sent[0])).toBe('legacy-id');
      expect(storage.getItem(PREFIXED_KEY)).toBe('legacy-id');
      expect(randomUUID).not.toHaveBeenCalled();
    });
  });

  describe('StorageManager device id key', () => {
    test('with prefix "myapp" the device id is stored under myapp_passflowDeviceId', () => {
      const storageManager = new StorageManager({ storage, prefix: 'myapp' });

      expect(storageManager.deviceId).toBe(PREFIXED_KEY);

      storageManager.setDeviceId('id-1');

      expect(storage.getItem(PREFIXED_KEY)).toBe('id-1');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('without a prefix the key stays passflowDeviceId', () => {
      const storageManager = new StorageManager({ storage });

      expect(storageManager.deviceId).toBe(LEGACY_KEY);

      storageManager.setDeviceId('id-1');

      expect(storage.getItem(LEGACY_KEY)).toBe('id-1');
    });

    test('a legacy unprefixed id is adopted and moved to the prefixed key', () => {
      storage.setItem(LEGACY_KEY, 'legacy-id');
      const storageManager = new StorageManager({ storage, prefix: 'myapp' });

      expect(storageManager.getDeviceId()).toBe('legacy-id');
      expect(storage.getItem(PREFIXED_KEY)).toBe('legacy-id');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('deleteDeviceId removes both the prefixed and the legacy key', () => {
      storage.setItem(LEGACY_KEY, 'legacy-id');
      storage.setItem(PREFIXED_KEY, 'current-id');
      const storageManager = new StorageManager({ storage, prefix: 'myapp' });

      storageManager.deleteDeviceId();

      expect(storage.getItem(PREFIXED_KEY)).toBeNull();
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
      expect(storageManager.getDeviceId()).toBeUndefined();
    });
  });
});
