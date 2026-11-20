/**
 * The scopes, invitation token and previous redirect URL keys honour the storage prefix. A value
 * stored under the unprefixed key is moved to the prefixed key on first read, and a delete removes
 * both keys.
 */

import { beforeEach, describe, expect, test } from 'vitest';
import { StorageManager } from '../../lib/storage';
import { FakeStorage } from './fake-storage';

const PREFIX = 'myapp';

describe('prefixed storage keys', () => {
  let storage: FakeStorage;

  beforeEach(() => {
    storage = new FakeStorage();
  });

  describe('scopes', () => {
    const LEGACY_KEY = 'tokens_scopes';
    const PREFIXED_KEY = 'myapp_tokens_scopes';

    test('with prefix "myapp" the scopes are stored under myapp_tokens_scopes', () => {
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.scopes).toBe(PREFIXED_KEY);

      storageManager.saveTokens({ access_token: 'access', scopes: ['id', 'email'] });

      expect(storage.getItem(PREFIXED_KEY)).toBe('id,email');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('unprefixed scopes are read by getScopes and moved to the prefixed key', () => {
      storage.setItem(LEGACY_KEY, 'id,email');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.getScopes()).toEqual(['id', 'email']);
      expect(storage.getItem(PREFIXED_KEY)).toBe('id,email');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('unprefixed scopes are read by getTokens and moved to the prefixed key', () => {
      storage.setItem(LEGACY_KEY, 'id,email');
      storage.setItem('myapp_access', 'access');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.getTokens()?.scopes).toEqual(['id', 'email']);
      expect(storage.getItem(PREFIXED_KEY)).toBe('id,email');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('deleteTokens removes both the prefixed and the unprefixed scopes', () => {
      storage.setItem(LEGACY_KEY, 'old');
      storage.setItem(PREFIXED_KEY, 'current');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      storageManager.deleteTokens();

      expect(storage.getItem(PREFIXED_KEY)).toBeNull();
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
      expect(storageManager.getScopes()).toBeUndefined();
    });

    test('a stored empty scope list is kept, not replaced by unprefixed scopes', () => {
      storage.setItem(LEGACY_KEY, 'old');
      storage.setItem(PREFIXED_KEY, '');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.getScopes()).not.toEqual(['old']);
      expect(storage.getItem(PREFIXED_KEY)).toBe('');
    });
  });

  describe('invitation token', () => {
    const LEGACY_KEY = 'passflowInvitationToken';
    const PREFIXED_KEY = 'myapp_passflowInvitationToken';

    test('with prefix "myapp" the invitation token is stored under myapp_passflowInvitationToken', () => {
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.invitationToken).toBe(PREFIXED_KEY);

      storageManager.setInvitationToken('invite-1');

      expect(storage.getItem(PREFIXED_KEY)).toBe('invite-1');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('an unprefixed invitation token is read and moved to the prefixed key', () => {
      storage.setItem(LEGACY_KEY, 'old-invite');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.getInvitationToken()).toBe('old-invite');
      expect(storage.getItem(PREFIXED_KEY)).toBe('old-invite');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('deleteInvitationToken removes both the prefixed and the unprefixed key', () => {
      storage.setItem(LEGACY_KEY, 'old-invite');
      storage.setItem(PREFIXED_KEY, 'current-invite');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      storageManager.deleteInvitationToken();

      expect(storage.getItem(PREFIXED_KEY)).toBeNull();
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
      expect(storageManager.getInvitationToken()).toBeUndefined();
    });
  });

  describe('previous redirect URL', () => {
    const LEGACY_KEY = 'passflowPreviousRedirectUrl';
    const PREFIXED_KEY = 'myapp_passflowPreviousRedirectUrl';

    test('with prefix "myapp" the URL is stored under myapp_passflowPreviousRedirectUrl', () => {
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.previousRedirectUrl).toBe(PREFIXED_KEY);

      storageManager.setPreviousRedirectUrl('https://app.example.com/a');

      expect(storage.getItem(PREFIXED_KEY)).toBe('https://app.example.com/a');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('an unprefixed URL is read and moved to the prefixed key', () => {
      storage.setItem(LEGACY_KEY, 'https://app.example.com/old');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      expect(storageManager.getPreviousRedirectUrl()).toBe('https://app.example.com/old');
      expect(storage.getItem(PREFIXED_KEY)).toBe('https://app.example.com/old');
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
    });

    test('deletePreviousRedirectUrl removes both the prefixed and the unprefixed key', () => {
      storage.setItem(LEGACY_KEY, 'https://app.example.com/old');
      storage.setItem(PREFIXED_KEY, 'https://app.example.com/current');
      const storageManager = new StorageManager({ storage, prefix: PREFIX });

      storageManager.deletePreviousRedirectUrl();

      expect(storage.getItem(PREFIXED_KEY)).toBeNull();
      expect(storage.getItem(LEGACY_KEY)).toBeNull();
      expect(storageManager.getPreviousRedirectUrl()).toBeUndefined();
    });
  });
});
