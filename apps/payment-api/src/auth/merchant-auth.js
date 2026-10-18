import { HttpServer } from '../server.js';
import { MerchantApiKeyScopes } from '@youpi/db';

function readBearerToken(req) {
  const authHeader = (req.headers?.authorization || req.headers?.Authorization || '').trim();
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  return token || null;
}

function hasAllScopes(key, requiredScopes = []) {
  if (!requiredScopes || requiredScopes.length === 0) return true;
  const keyScopes = new Set(Array.isArray(key.scopes) ? key.scopes : []);
  return requiredScopes.every(scope => keyScopes.has(scope));
}

/**
 * Merchant auth resolver supporting bearer API keys and legacy merchant headers.
 * - If Authorization bearer token is provided, token auth is enforced.
 * - If token is absent, falls back to x-merchant-id / x-api-key for backwards compatibility.
 */
export function resolveMerchantAuth(req, res, ctx, options = {}) {
  const token = readBearerToken(req);

  if (token) {
    if (!ctx.apiKeyRepo) {
      HttpServer.json(res, 500, { error: 'Merchant API key repository not configured.' });
      return null;
    }

    const key = ctx.apiKeyRepo.authenticate(token);
    if (!key || !key.isActive) {
      HttpServer.json(res, 401, { error: 'Invalid merchant API key.' });
      return null;
    }

    if (!hasAllScopes(key, options.requiredScopes || [])) {
      HttpServer.json(res, 403, {
        error: 'Forbidden: API key does not have required scope.',
        requiredScopes: options.requiredScopes || []
      });
      return null;
    }

    const merchant = ctx.merchantRepo.findById(key.merchantId);
    if (!merchant) {
      HttpServer.json(res, 401, { error: 'Invalid merchant API key context.' });
      return null;
    }

    return { merchant, apiKey: key, authType: 'bearer_api_key' };
  }

  const fallbackMerchantId = options.fallbackMerchantId || null;
  const merchantId =
    req.headers?.['x-merchant-id'] ||
    req.headers?.['x-api-key'] ||
    req.query?.merchantId ||
    fallbackMerchantId ||
    null;

  let merchant = null;
  if (merchantId) {
    merchant = ctx.merchantRepo.findById(merchantId);
  } else if (options.allowDefault !== false) {
    merchant = ctx.merchantRepo.getDefault
      ? ctx.merchantRepo.getDefault()
      : (ctx.merchantRepo.findById('00000000-0000-0000-0000-000000000001') || ctx.merchantRepo.findAll()[0]);
  }

  if (!merchant) {
    HttpServer.json(res, options.onLegacyMissingStatus || 401, {
      error: options.onLegacyMissingMessage || 'Merchant authentication required.'
    });
    return null;
  }

  return { merchant, apiKey: null, authType: 'legacy_merchant_id' };
}

export const MerchantScopes = MerchantApiKeyScopes;
