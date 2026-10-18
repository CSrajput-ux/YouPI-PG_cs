import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Database, runMigrations, MerchantApiKeyRepository } from '../index.js';

describe('MerchantApiKeyRepository', () => {
  let db;
  let apiKeyRepo;
  let defaultMerchant;

  beforeEach(() => {
    db = new Database({ inMemory: true });
    ({ defaultMerchant } = runMigrations(db));
    apiKeyRepo = new MerchantApiKeyRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  test('creates test and live keys with hashed secret and single-use secret return', () => {
    const created = apiKeyRepo.create({
      merchantId: defaultMerchant.id,
      environment: 'test',
      scopes: ['read', 'write']
    });

    assert.ok(created.id);
    assert.ok(created.keyId.startsWith('ypg_test_pk_'));
    assert.ok(created.rawSecret.startsWith('ypg_test_sk_'));
    assert.notEqual(created.secretHash, created.rawSecret);

    const fetched = apiKeyRepo.findById(created.id);
    assert.ok(fetched);
    assert.equal(fetched.secretHash, created.secretHash);
    assert.equal(fetched.rawSecret, undefined);

    const live = apiKeyRepo.create({
      merchantId: defaultMerchant.id,
      environment: 'live'
    });
    assert.ok(live.keyId.startsWith('ypg_live_pk_'));
    assert.ok(live.rawSecret.startsWith('ypg_live_sk_'));
  });

  test('authenticates active key, rotates secret, and revokes key', () => {
    const created = apiKeyRepo.create({
      merchantId: defaultMerchant.id,
      environment: 'test'
    });

    const auth = apiKeyRepo.authenticate(created.rawSecret);
    assert.ok(auth);
    assert.equal(auth.merchantId, defaultMerchant.id);

    const rotated = apiKeyRepo.rotate(created.id, defaultMerchant.id);
    assert.ok(rotated);
    assert.notEqual(rotated.rawSecret, created.rawSecret);

    const oldAfterRotate = apiKeyRepo.authenticate(created.rawSecret);
    assert.equal(oldAfterRotate, null);

    const newAfterRotate = apiKeyRepo.authenticate(rotated.rawSecret);
    assert.ok(newAfterRotate);

    const revoked = apiKeyRepo.revoke(created.id, defaultMerchant.id);
    assert.ok(revoked);
    assert.equal(revoked.isActive, false);

    const authAfterRevoke = apiKeyRepo.authenticate(rotated.rawSecret);
    assert.equal(authAfterRevoke, null);
  });
});
