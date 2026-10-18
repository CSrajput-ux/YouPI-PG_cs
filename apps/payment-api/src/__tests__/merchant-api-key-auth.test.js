import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Database } from '@youpi/db';
import { startServer as startPaymentApi } from '../index.js';

describe('Merchant API key management and bearer auth', () => {
  let apiInstance;
  let baseUrl;
  let testDb;
  const merchantId = '00000000-0000-0000-0000-000000000001';

  before(async () => {
    testDb = new Database({ inMemory: true });
    apiInstance = await startPaymentApi(6211, testDb);
    baseUrl = `http://localhost:${apiInstance.port}`;
  });

  after(async () => {
    if (apiInstance) await apiInstance.close();
    if (testDb) testDb.close();
  });

  function request(path, options = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      };

      const req = http.request(url, {
        method: options.method || 'GET',
        headers
      }, res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          let body;
          try {
            body = JSON.parse(data);
          } catch {
            body = data;
          }
          resolve({ status: res.statusCode, body });
        });
      });

      req.on('error', reject);
      if (options.body) {
        req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
      }
      req.end();
    });
  }

  test('creates, lists, rotates and revokes merchant API keys', async () => {
    const createRes = await request('/api/v1/admin/api-keys', {
      method: 'POST',
      headers: { 'x-merchant-id': merchantId },
      body: {
        name: 'CI key',
        environment: 'test',
        scopes: ['read', 'write', 'settlements_admin']
      }
    });

    assert.equal(createRes.status, 201);
    assert.ok(createRes.body.apiKeySecret);
    assert.ok(createRes.body.keyId.startsWith('ypg_test_pk_'));
    assert.ok(createRes.body.apiKeySecret.startsWith('ypg_test_sk_'));
    assert.equal(createRes.body.key.maskedSecret.includes(createRes.body.apiKeySecret), false);

    const keyId = createRes.body.key.id;
    const firstSecret = createRes.body.apiKeySecret;

    const listRes = await request('/api/v1/admin/api-keys?merchantId=' + merchantId, {
      headers: { 'x-merchant-id': merchantId }
    });
    assert.equal(listRes.status, 200);
    assert.ok(Array.isArray(listRes.body.keys));
    assert.ok(listRes.body.keys.some(k => k.id === keyId));

    const rotateRes = await request(`/api/v1/admin/api-keys/${keyId}/rotate`, {
      method: 'POST',
      headers: { 'x-merchant-id': merchantId }
    });
    assert.equal(rotateRes.status, 200);
    assert.ok(rotateRes.body.apiKeySecret);
    assert.notEqual(rotateRes.body.apiKeySecret, firstSecret);

    const revokeRes = await request(`/api/v1/admin/api-keys/${keyId}/revoke`, {
      method: 'POST',
      headers: { 'x-merchant-id': merchantId }
    });
    assert.equal(revokeRes.status, 200);
    assert.equal(revokeRes.body.success, true);
    assert.equal(revokeRes.body.key.isActive, false);
  });

  test('authenticates bearer key with write scope and rejects write when scope missing', async () => {
    const writeKey = await request('/api/v1/admin/api-keys', {
      method: 'POST',
      headers: { 'x-merchant-id': merchantId },
      body: {
        name: 'Write key',
        environment: 'test',
        scopes: ['read', 'write', 'settlements_admin']
      }
    });
    assert.equal(writeKey.status, 201);

    const createPayment = await request('/api/v1/payments', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + writeKey.body.apiKeySecret
      },
      body: {
        orderId: 'ORD-BEARER-WRITE-1',
        amount: 199
      }
    });
    assert.equal(createPayment.status, 201);
    assert.ok(createPayment.body.paymentId);

    const readOnlyKey = await request('/api/v1/admin/api-keys', {
      method: 'POST',
      headers: { 'x-merchant-id': merchantId },
      body: {
        name: 'Read key',
        environment: 'test',
        scopes: ['read']
      }
    });
    assert.equal(readOnlyKey.status, 201);

    const deniedPayment = await request('/api/v1/payments', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + readOnlyKey.body.apiKeySecret
      },
      body: {
        orderId: 'ORD-BEARER-DENY-1',
        amount: 200
      }
    });

    assert.equal(deniedPayment.status, 403);
    assert.equal(typeof deniedPayment.body.error, 'string');
  });
});
