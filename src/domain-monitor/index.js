import { checkAuth, simpleAuthResponse } from '../middleware/auth.js';
import { initDatabase } from '../database/schema.js';
import { loadSiteSettings } from '../utils/settings.js';
import { sendNotification } from '../services/notification.js';
import {
  createBadRequestResponse,
  createErrorResponse,
  createNotFoundResponse,
  createSuccessResponse
} from '../utils/errors.js';
import { alertTier, checkRegistration, checkTlsCertificate, normalizeDomainInput } from './checks.js';

const DAY_MS = 86400000;
const RETRY_MS = 6 * 60 * 60 * 1000;
const CHECK_BATCH_SIZE = 4;

export async function initDomainDatabase(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS domain_monitors (
      id TEXT PRIMARY KEY,
      domain TEXT NOT NULL,
      tls_host TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      reminder_days INTEGER NOT NULL DEFAULT 30,
      registration_expires_at INTEGER,
      registration_checked_at INTEGER,
      registration_error TEXT,
      registration_source TEXT,
      next_registration_check_at INTEGER NOT NULL DEFAULT 0,
      registration_alert_key TEXT,
      tls_not_after INTEGER,
      tls_not_before INTEGER,
      tls_checked_at INTEGER,
      tls_error TEXT,
      tls_authorized INTEGER,
      tls_hostname_valid INTEGER,
      tls_issuer TEXT,
      tls_fingerprint TEXT,
      next_tls_check_at INTEGER NOT NULL DEFAULT 0,
      tls_alert_key TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      UNIQUE(domain, tls_host)
    )
  `).run();
}

async function getMonitor(db, id) {
  return db.prepare('SELECT * FROM domain_monitors WHERE id = ?').bind(id).first();
}

function hasNotificationTarget(settings) {
  if (settings.notification_webhook_enabled === 'true' || settings.notification_webhook_enabled === true) {
    return Boolean(String(settings.notification_webhook_url || '').trim());
  }
  return Boolean(String(settings.tg_bot_token || '').trim());
}

function notificationText(row, kind, days, settings) {
  const title = row.label || (kind === 'tls' ? row.tls_host : row.domain);
  const date = new Date(kind === 'tls' ? row.tls_not_after : row.registration_expires_at).toISOString().slice(0, 10);
  const language = settings.notification_language;
  if (language === 'en') {
    return {
      event: kind === 'tls' ? 'TLS certificate expiration' : 'Domain registration expiration',
      message: `${title} (${kind === 'tls' ? row.tls_host : row.domain}): ${days <= 0 ? 'expired' : `${days} days left`}, ${date}`
    };
  }
  if (language === 'es') {
    return {
      event: kind === 'tls' ? 'Vencimiento del certificado TLS' : 'Vencimiento del dominio',
      message: `${title} (${kind === 'tls' ? row.tls_host : row.domain}): ${days <= 0 ? 'vencido' : `${days} días restantes`}, ${date}`
    };
  }
  return {
    event: kind === 'tls' ? 'SSL 证书到期' : '域名注册到期',
    message: `${title}（${kind === 'tls' ? row.tls_host : row.domain}）：${days <= 0 ? '已到期' : `剩余 ${days} 天`}，到期日 ${date}`
  };
}

async function maybeNotify(db, row, kind, settings, now, notifier = sendNotification) {
  if (!hasNotificationTarget(settings)) return;
  const expiration = kind === 'tls' ? row.tls_not_after : row.registration_expires_at;
  const alert = alertTier(expiration, row.reminder_days, now);
  if (!alert) return;
  const field = kind === 'tls' ? 'tls_alert_key' : 'registration_alert_key';
  const key = `${expiration}:${alert.tier}`;
  if (row[field] === key) return;

  const { event, message } = notificationText(row, kind, alert.days, settings);
  const error = await notifier(settings, message, {
    event,
    emoji: '⚠️',
    clients: [row.label || row.domain],
    count: 1,
    message
  });
  if (error) {
    console.warn(`[DomainMonitor] ${kind} notification failed:`, error);
    return;
  }
  await db.prepare(`UPDATE domain_monitors SET ${field} = ? WHERE id = ?`).bind(key, row.id).run();
  row[field] = key;
}

async function saveTlsCheck(db, row, result, settings, now, notifier = sendNotification) {
  if (result.error) {
    const message = String(result.error).slice(0, 300);
    await db.prepare(`
      UPDATE domain_monitors SET tls_checked_at = ?, tls_error = ?, next_tls_check_at = ? WHERE id = ?
    `).bind(now, message, now + RETRY_MS, row.id).run();
    console.warn(`[DomainMonitor] TLS check failed for ${row.tls_host}:`, message);
    return;
  }

  const expiresAt = Number(result.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
    throw new Error('TLS result has no valid expiration date');
  }
  const validationError = result.validationError || (!result.authorized ? 'Certificate validation failed' : '');
  await db.prepare(`
    UPDATE domain_monitors SET tls_not_after = ?, tls_not_before = ?, tls_checked_at = ?,
      tls_error = ?, tls_authorized = ?, tls_hostname_valid = ?, tls_issuer = ?,
      tls_fingerprint = ?, next_tls_check_at = ? WHERE id = ?
  `).bind(
    expiresAt, result.notBefore ?? null, now, validationError || null,
    Number(result.authorized), Number(result.hostnameValid), String(result.issuer || '').slice(0, 200),
    String(result.fingerprint || '').slice(0, 100), now + DAY_MS, row.id
  ).run();
  row.tls_not_after = expiresAt;
  row.tls_error = validationError || null;
  try {
    await maybeNotify(db, row, 'tls', settings, now, notifier);
  } catch (error) {
    console.warn('[DomainMonitor] TLS notification failed:', error);
  }
}

export async function checkDomainMonitor(db, id, options = {}) {
  const now = options.now || Date.now();
  const row = await getMonitor(db, id);
  if (!row) return null;
  const settings = options.settings || await loadSiteSettings(db);
  const force = options.force === true;

  if (force || row.next_registration_check_at <= now) {
    try {
      const result = await (options.registrationChecker || checkRegistration)(row.domain);
      await db.prepare(`
        UPDATE domain_monitors SET registration_expires_at = ?, registration_source = ?,
          registration_checked_at = ?, registration_error = NULL, next_registration_check_at = ?
        WHERE id = ?
      `).bind(result.expiresAt, result.source, now, now + DAY_MS, id).run();
      row.registration_expires_at = result.expiresAt;
      row.registration_source = result.source;
      row.registration_error = null;
      try {
        await maybeNotify(db, row, 'registration', settings, now, options.notifier);
      } catch (error) {
        console.warn('[DomainMonitor] Registration notification failed:', error);
      }
    } catch (error) {
      const message = String(error?.message || error).slice(0, 300);
      await db.prepare(`
        UPDATE domain_monitors SET registration_checked_at = ?, registration_error = ?, next_registration_check_at = ?
        WHERE id = ?
      `).bind(now, message, now + RETRY_MS, id).run();
      console.warn(`[DomainMonitor] RDAP check failed for ${row.domain}:`, message);
    }
  }

  if (!options.externalTls && (force || row.next_tls_check_at <= now)) {
    try {
      const result = await (options.tlsChecker || checkTlsCertificate)(row.tls_host);
      await saveTlsCheck(db, row, result, settings, now, options.notifier);
    } catch (error) {
      await saveTlsCheck(db, row, { error: error?.message || String(error) }, settings, now, options.notifier);
    }
  }
  return getMonitor(db, id);
}

export async function checkDueDomainMonitors(env) {
  await initDatabase(env.DB);
  await initDomainDatabase(env.DB);
  const now = Date.now();
  const externalTls = Boolean(env.DOMAIN_PROBE_SECRET);
  const due = externalTls
    ? await env.DB.prepare(`
      SELECT id FROM domain_monitors WHERE enabled = 1 AND next_registration_check_at <= ?
      ORDER BY next_registration_check_at, created_at LIMIT ?
    `).bind(now, CHECK_BATCH_SIZE).all()
    : await env.DB.prepare(`
      SELECT id FROM domain_monitors WHERE enabled = 1
        AND (next_registration_check_at <= ? OR next_tls_check_at <= ?)
      ORDER BY MIN(next_registration_check_at, next_tls_check_at), created_at LIMIT ?
    `).bind(now, now, CHECK_BATCH_SIZE).all();
  if (!due.results?.length) return;
  const settings = await loadSiteSettings(env.DB);
  await Promise.all(due.results.map(async row => {
    try {
      await checkDomainMonitor(env.DB, row.id, { now, settings, externalTls });
    } catch (error) {
      console.error(`[DomainMonitor] check failed for ${row.id}:`, error);
    }
  }));
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function handleDomainMonitorRequest(request, env) {
  try {
    await initDatabase(env.DB);
    const settings = await loadSiteSettings(env.DB);
    if (!await checkAuth(request, env, settings)) return simpleAuthResponse();
    await initDomainDatabase(env.DB);

    const path = new URL(request.url).pathname;
    const segments = path.slice('/api/admin/domains'.length).split('/').filter(Boolean);
    const id = segments[0];
    const method = request.method;

    if (segments.length === 0 && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM domain_monitors ORDER BY created_at DESC').all();
      return createSuccessResponse({ domains: results || [], tls_probe_mode: env.DOMAIN_PROBE_SECRET ? 'external' : 'worker' });
    }

    if (segments.length === 0 && method === 'POST') {
      const input = normalizeDomainInput(await request.json());
      const now = Date.now();
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare(`
          INSERT INTO domain_monitors (id, domain, tls_host, label, enabled, reminder_days, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(id, input.domain, input.tls_host, input.label, input.enabled, input.reminder_days, now, now).run();
      } catch (error) {
        if (/UNIQUE constraint failed/i.test(String(error?.message))) return createBadRequestResponse('Domain and TLS host already exist');
        throw error;
      }
      return jsonResponse(await getMonitor(env.DB, id), 201);
    }

    if (!/^[0-9a-f-]{36}$/i.test(id || '') || segments.length > 2) return createNotFoundResponse();
    const existing = await getMonitor(env.DB, id);
    if (!existing) return createNotFoundResponse();

    if (segments.length === 1 && method === 'PUT') {
      const input = normalizeDomainInput({ ...existing, ...await request.json() });
      const changedTarget = input.domain !== existing.domain || input.tls_host !== existing.tls_host;
      try {
        await env.DB.prepare(`
          UPDATE domain_monitors SET domain = ?, tls_host = ?, label = ?, enabled = ?, reminder_days = ?,
            registration_expires_at = ?, registration_checked_at = ?, registration_error = ?, registration_source = ?,
            registration_alert_key = ?, next_registration_check_at = ?, tls_not_after = ?,
            tls_not_before = ?, tls_checked_at = ?, tls_error = ?, tls_authorized = ?,
            tls_hostname_valid = ?, tls_issuer = ?, tls_fingerprint = ?,
            tls_alert_key = ?, next_tls_check_at = ?, updated_at = ? WHERE id = ?
        `).bind(
          input.domain, input.tls_host, input.label, input.enabled, input.reminder_days,
          changedTarget ? null : existing.registration_expires_at,
          changedTarget ? null : existing.registration_checked_at,
          changedTarget ? null : existing.registration_error,
          changedTarget ? null : existing.registration_source,
          changedTarget ? null : existing.registration_alert_key,
          changedTarget ? 0 : existing.next_registration_check_at,
          changedTarget ? null : existing.tls_not_after,
          changedTarget ? null : existing.tls_not_before,
          changedTarget ? null : existing.tls_checked_at,
          changedTarget ? null : existing.tls_error,
          changedTarget ? null : existing.tls_authorized,
          changedTarget ? null : existing.tls_hostname_valid,
          changedTarget ? null : existing.tls_issuer,
          changedTarget ? null : existing.tls_fingerprint,
          changedTarget ? null : existing.tls_alert_key,
          changedTarget ? 0 : existing.next_tls_check_at,
          Date.now(), id
        ).run();
      } catch (error) {
        if (/UNIQUE constraint failed/i.test(String(error?.message))) return createBadRequestResponse('Domain and TLS host already exist');
        throw error;
      }
      return createSuccessResponse(await getMonitor(env.DB, id));
    }

    if (segments.length === 1 && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM domain_monitors WHERE id = ?').bind(id).run();
      return createSuccessResponse({ success: true });
    }

    if (segments.length === 2 && segments[1] === 'check' && method === 'POST') {
      return createSuccessResponse(await checkDomainMonitor(env.DB, id, {
        force: true,
        settings,
        externalTls: Boolean(env.DOMAIN_PROBE_SECRET)
      }));
    }
    return createNotFoundResponse();
  } catch (error) {
    if (error instanceof SyntaxError || /^(Enter a registered domain|Reminder days|Label is too long)/.test(error?.message || '')) {
      return createBadRequestResponse(error.message);
    }
    return createErrorResponse(error);
  }
}

async function isProbeAuthorized(request, secret) {
  if (!secret || secret.length < 16) return false;
  const token = request.headers.get('Authorization') || '';
  const supplied = token.startsWith('Bearer ') ? token.slice(7) : '';
  if (!supplied) return false;
  const encoder = new TextEncoder();
  const [expectedHash, suppliedHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(secret)),
    crypto.subtle.digest('SHA-256', encoder.encode(supplied))
  ]);
  const expected = new Uint8Array(expectedHash);
  const actual = new Uint8Array(suppliedHash);
  let difference = 0;
  for (let index = 0; index < expected.length; index++) difference |= expected[index] ^ actual[index];
  return difference === 0;
}

export async function handleDomainProbeRequest(request, env) {
  if (!env.DOMAIN_PROBE_SECRET) return createNotFoundResponse();
  if (!await isProbeAuthorized(request, String(env.DOMAIN_PROBE_SECRET))) return simpleAuthResponse();

  try {
    await initDatabase(env.DB);
    await initDomainDatabase(env.DB);
    const url = new URL(request.url);
    if (url.pathname === '/api/domain-probe/jobs' && request.method === 'GET') {
      const after = url.searchParams.get('after') || '';
      if (after && !/^[0-9a-f-]{36}$/i.test(after)) return createBadRequestResponse('Invalid cursor');
      const { results } = await env.DB.prepare(`
        SELECT id, tls_host FROM domain_monitors WHERE enabled = 1 AND id > ? ORDER BY id LIMIT 100
      `).bind(after).all();
      const jobs = results || [];
      return createSuccessResponse({ jobs, next_cursor: jobs.length === 100 ? jobs.at(-1).id : null });
    }

    if (url.pathname === '/api/domain-probe/results' && request.method === 'POST') {
      const body = await request.json();
      if (!Array.isArray(body?.results) || body.results.length > 20) {
        return createBadRequestResponse('Expected up to 20 probe results');
      }
      const settings = await loadSiteSettings(env.DB);
      const now = Date.now();
      let accepted = 0;
      for (const entry of body.results) {
        if (!/^[0-9a-f-]{36}$/i.test(entry?.id || '')) continue;
        const row = await getMonitor(env.DB, entry.id);
        if (!row || !row.enabled || row.tls_host !== entry.tls_host) continue;
        const result = entry.result;
        if (!result || typeof result !== 'object') continue;
        if (result.error) {
          await saveTlsCheck(env.DB, row, { error: result.error }, settings, now);
        } else if (Number.isFinite(result.expiresAt) && result.expiresAt > 0 &&
          typeof result.authorized === 'boolean' && typeof result.hostnameValid === 'boolean') {
          await saveTlsCheck(env.DB, row, result, settings, now);
        } else {
          continue;
        }
        accepted++;
      }
      return createSuccessResponse({ accepted });
    }
    return createNotFoundResponse();
  } catch (error) {
    if (error instanceof SyntaxError) return createBadRequestResponse('Invalid JSON');
    return createErrorResponse(error);
  }
}
