import crypto from 'node:crypto';

const DEFAULT_SCOPES = ['read', 'write', 'refunds', 'webhooks', 'settlements_admin'];

function randomToken(bytes = 12) {
  return crypto.randomBytes(bytes).toString('hex');
}

function normalizeEnvironment(value) {
  return value === 'live' ? 'live' : 'test';
}

function environmentPrefix(environment) {
  return environment === 'live' ? 'ypg_live' : 'ypg_test';
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret, 'utf8').digest('hex');
}

function safeCompareHex(left, right) {
  try {
    const a = Buffer.from(left || '', 'hex');
    const b = Buffer.from(right || '', 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export class MerchantApiKeyRepository {
  /**
   * @param {import('../database.js').Database} db
   */
  constructor(db) {
    this.db = db;
  }

  create(data) {
    const now = new Date().toISOString();
    const id = data.id || crypto.randomUUID();
    const environment = normalizeEnvironment(data.environment);
    const prefix = environmentPrefix(environment);
    const keyId = `${prefix}_pk_${randomToken(8)}`;
    const rawSecret = `${prefix}_sk_${randomToken(24)}`;
    const secretHash = hashSecret(rawSecret);
    const secretLast4 = rawSecret.slice(-4);
    const name = (data.name || '').trim() || null;
    const scopes = Array.isArray(data.scopes) && data.scopes.length > 0
      ? [...new Set(data.scopes.map(scope => String(scope).trim()).filter(Boolean))]
      : [...DEFAULT_SCOPES];

    this.db.execute(`
      INSERT INTO merchant_api_keys
        (id, merchant_id, key_id, key_name, environment, secret_hash, secret_last4, scopes, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `, [
      id,
      data.merchantId,
      keyId,
      name,
      environment,
      secretHash,
      secretLast4,
      JSON.stringify(scopes),
      now,
      now
    ]);

    const created = this.findById(id);
    return {
      ...created,
      rawSecret
    };
  }

  findById(id) {
    const row = this.db.queryOne('SELECT * FROM merchant_api_keys WHERE id = ?', [id]);
    if (!row) return null;
    return this.mapRow(row);
  }

  findByKeyId(keyId) {
    const row = this.db.queryOne('SELECT * FROM merchant_api_keys WHERE key_id = ?', [keyId]);
    if (!row) return null;
    return this.mapRow(row);
  }

  listByMerchantId(merchantId, options = {}) {
    const includeRevoked = Boolean(options.includeRevoked);
    const rows = this.db.query(`
      SELECT * FROM merchant_api_keys
      WHERE merchant_id = ? ${includeRevoked ? '' : 'AND is_active = 1'}
      ORDER BY created_at DESC
    `, [merchantId]);
    return rows.map(row => this.mapRow(row));
  }

  revoke(id, merchantId = null) {
    const current = this.findById(id);
    if (!current) return null;
    if (merchantId && current.merchantId !== merchantId) return null;

    this.db.execute(`
      UPDATE merchant_api_keys
      SET is_active = 0,
          revoked_at = ?,
          updated_at = ?
      WHERE id = ?
    `, [new Date().toISOString(), new Date().toISOString(), id]);

    return this.findById(id);
  }

  rotate(id, merchantId = null) {
    const current = this.findById(id);
    if (!current) return null;
    if (merchantId && current.merchantId !== merchantId) return null;
    if (!current.isActive) return null;

    const prefix = environmentPrefix(current.environment);
    const rawSecret = `${prefix}_sk_${randomToken(24)}`;
    const now = new Date().toISOString();

    this.db.execute(`
      UPDATE merchant_api_keys
      SET secret_hash = ?,
          secret_last4 = ?,
          rotated_at = ?,
          updated_at = ?
      WHERE id = ?
    `, [hashSecret(rawSecret), rawSecret.slice(-4), now, now, id]);

    const updated = this.findById(id);
    return {
      ...updated,
      rawSecret
    };
  }

  authenticate(rawSecret) {
    if (!rawSecret || typeof rawSecret !== 'string') return null;

    const hashed = hashSecret(rawSecret.trim());
    const row = this.db.queryOne(`
      SELECT * FROM merchant_api_keys
      WHERE secret_hash = ?
        AND is_active = 1
      LIMIT 1
    `, [hashed]);

    if (!row) return null;
    if (!safeCompareHex(row.secret_hash, hashed)) return null;

    const now = new Date().toISOString();
    this.db.execute('UPDATE merchant_api_keys SET last_used_at = ?, updated_at = ? WHERE id = ?', [now, now, row.id]);

    return this.mapRow({ ...row, last_used_at: now, updated_at: now });
  }

  maskForList(key) {
    return {
      id: key.id,
      merchantId: key.merchantId,
      keyId: key.keyId,
      name: key.name,
      environment: key.environment,
      scopes: key.scopes,
      isActive: key.isActive,
      revokedAt: key.revokedAt,
      lastUsedAt: key.lastUsedAt,
      createdAt: key.createdAt,
      updatedAt: key.updatedAt,
      rotatedAt: key.rotatedAt,
      maskedSecret: `${environmentPrefix(key.environment)}_sk_••••${key.secretLast4}`
    };
  }

  mapRow(row) {
    return {
      id: row.id,
      merchantId: row.merchant_id,
      keyId: row.key_id,
      name: row.key_name,
      environment: row.environment,
      secretHash: row.secret_hash,
      secretLast4: row.secret_last4,
      scopes: JSON.parse(row.scopes || '[]'),
      isActive: Boolean(row.is_active),
      revokedAt: row.revoked_at ? new Date(row.revoked_at) : null,
      lastUsedAt: row.last_used_at ? new Date(row.last_used_at) : null,
      createdAt: row.created_at ? new Date(row.created_at) : null,
      updatedAt: row.updated_at ? new Date(row.updated_at) : null,
      rotatedAt: row.rotated_at ? new Date(row.rotated_at) : null
    };
  }
}

export const MerchantApiKeyScopes = {
  READ: 'read',
  WRITE: 'write',
  REFUNDS: 'refunds',
  WEBHOOKS: 'webhooks',
  SETTLEMENTS_ADMIN: 'settlements_admin'
};

export const DEFAULT_MERCHANT_API_KEY_SCOPES = [...DEFAULT_SCOPES];
