import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import {
  alertTier,
  checkRegistration,
  checkTlsCertificate,
  clearRdapBootstrapCache,
  normalizeDomainInput,
  parseRdapExpiration
} from '../src/domain-monitor/checks.js';
import {
  checkDomainMonitor,
  handleDomainMonitorRequest,
  handleDomainProbeRequest,
  initDomainDatabase
} from '../src/domain-monitor/index.js';
import { initDatabase } from '../src/database/schema.js';
import { generateToken } from '../src/middleware/auth.js';
import { loadSiteSettings } from '../src/utils/settings.js';

function createDb() {
  const sqlite = new DatabaseSync(':memory:');
  return {
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      let parameters = [];
      return {
        bind(...values) {
          parameters = values;
          return this;
        },
        async run() { return statement.run(...parameters); },
        async first() { return statement.get(...parameters) || null; },
        async all() { return { results: statement.all(...parameters) }; }
      };
    },
    close() { sqlite.close(); }
  };
}

test('validates registration domain and certificate hostname separately', () => {
  assert.deepEqual(normalizeDomainInput({ domain: 'Example.COM.', tls_host: 'www.example.com', reminder_days: 14 }), {
    domain: 'example.com', tls_host: 'www.example.com', label: '', reminder_days: 14, enabled: 1
  });
  assert.equal(normalizeDomainInput({ domain: 'bücher.de' }).domain, 'xn--bcher-kva.de');
  assert.throws(() => normalizeDomainInput({ domain: 'example.com', tls_host: 'other.com' }));
  assert.throws(() => normalizeDomainInput({ domain: '127.0.0.1' }));
  assert.throws(() => normalizeDomainInput({ domain: 'example.com', reminder_days: 0 }));
});

test('uses registry RDAP data and treats missing expiry as unknown', async () => {
  clearRdapBootstrapCache();
  const calls = [];
  const fetcher = async url => {
    calls.push(url);
    if (calls.length === 1) return Response.json({ services: [[['com'], ['https://rdap.example/rdap/']]] });
    return Response.json({ events: [{ eventAction: 'expiration', eventDate: '2030-02-03T00:00:00Z' }] });
  };
  const result = await checkRegistration('example.com', { fetcher, now: 1000 });
  assert.equal(result.expiresAt, Date.parse('2030-02-03T00:00:00Z'));
  assert.equal(calls[1], 'https://rdap.example/rdap/domain/example.com');
  assert.equal(parseRdapExpiration({ events: [] }), null);
  clearRdapBootstrapCache();
});

test('concurrent registration checks share the IANA bootstrap request', async () => {
  clearRdapBootstrapCache();
  let bootstrapCalls = 0;
  const fetcher = async url => {
    if (url.includes('/rdap/dns.json')) {
      bootstrapCalls++;
      return Response.json({ services: [[['com'], ['https://rdap.example/rdap/']]] });
    }
    return Response.json({ events: [{ eventAction: 'expiration', eventDate: '2030-02-03T00:00:00Z' }] });
  };
  await Promise.all([
    checkRegistration('example.com', { fetcher, now: 1000 }),
    checkRegistration('another.com', { fetcher, now: 1000 })
  ]);
  assert.equal(bootstrapCalls, 1);
  clearRdapBootstrapCache();
});

test('extracts the presented TLS certificate expiry and hostname validity', async () => {
  const socket = new EventEmitter();
  socket.authorized = true;
  socket.destroy = () => {};
  socket.getPeerCertificate = () => ({
    valid_to: 'Jan  1 00:00:00 2030 GMT',
    valid_from: 'Jan  1 00:00:00 2026 GMT',
    subjectaltname: 'DNS:example.com',
    issuer: { CN: 'Example CA' },
    fingerprint256: 'AA:BB'
  });
  const promise = checkTlsCertificate('example.com', {
    connector: () => {
      queueMicrotask(() => socket.emit('secureConnect'));
      return socket;
    }
  });
  const result = await promise;
  assert.equal(result.expiresAt, Date.parse('Jan  1 00:00:00 2030 GMT'));
  assert.equal(result.hostnameValid, true);
  assert.equal(result.authorized, true);
  assert.equal(result.issuer, 'Example CA');
});

test('alert tiers advance without sending all earlier thresholds at once', () => {
  const now = Date.parse('2026-01-01T00:00:00Z');
  assert.equal(alertTier(null, 30, now), null);
  assert.equal(alertTier(now + 40 * 86400000, 30, now), null);
  assert.equal(alertTier(now + 5 * 86400000, 30, now).tier, 7);
  assert.equal(alertTier(now - 86400000, 30, now).tier, 0);
});

test('admin API is authenticated and stores domain monitors independently', async () => {
  const db = createDb();
  const env = { DB: db, API_SECRET: 'test-secret-for-domain-monitor' };
  await initDatabase(db);
  const settings = await loadSiteSettings(db);
  const token = await generateToken(env, settings);
  const request = (path, method = 'GET', body = null, authorized = true) => new Request(`https://monitor.test${path}`, {
    method,
    headers: {
      ...(authorized ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });

  assert.equal((await handleDomainMonitorRequest(request('/api/admin/domains', 'GET', null, false), env)).status, 401);
  const created = await handleDomainMonitorRequest(request('/api/admin/domains', 'POST', {
    domain: 'example.com', tls_host: 'www.example.com', reminder_days: 14
  }), env);
  assert.equal(created.status, 201);
  const monitor = await created.json();
  assert.equal(monitor.domain, 'example.com');

  const duplicate = await handleDomainMonitorRequest(request('/api/admin/domains', 'POST', {
    domain: 'example.com', tls_host: 'www.example.com'
  }), env);
  assert.equal(duplicate.status, 400);

  const updated = await handleDomainMonitorRequest(request(`/api/admin/domains/${monitor.id}`, 'PUT', {
    label: 'Production', enabled: false
  }), env);
  assert.equal((await updated.json()).enabled, 0);

  const listed = await handleDomainMonitorRequest(request('/api/admin/domains'), env);
  assert.equal((await listed.json()).domains.length, 1);
  assert.equal((await handleDomainMonitorRequest(request(`/api/admin/domains/${monitor.id}`, 'DELETE'), env)).status, 200);
  assert.equal((await (await handleDomainMonitorRequest(request('/api/admin/domains'), env)).json()).domains.length, 0);
  db.close();
});

test('check failures stay visible and successful alerts are deduplicated', async () => {
  const db = createDb();
  await initDomainDatabase(db);
  const now = Date.parse('2026-01-01T00:00:00Z');
  const id = crypto.randomUUID();
  await db.prepare(`INSERT INTO domain_monitors
    (id, domain, tls_host, reminder_days, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(id, 'example.com', 'www.example.com', 30, now, now).run();
  const notifications = [];
  const options = {
    now,
    force: true,
    settings: { tg_bot_token: 'configured', notification_language: 'en' },
    registrationChecker: async () => ({ expiresAt: now + 5 * 86400000, source: 'https://rdap.example/' }),
    tlsChecker: async () => ({ expiresAt: now + 20 * 86400000, notBefore: now, authorized: true, hostnameValid: true, issuer: 'CA', fingerprint: 'AB' }),
    notifier: async (_, message) => { notifications.push(message); }
  };
  await checkDomainMonitor(db, id, options);
  await checkDomainMonitor(db, id, options);
  assert.equal(notifications.length, 2);

  const failed = await checkDomainMonitor(db, id, {
    ...options,
    registrationChecker: async () => { throw new Error('RDAP unavailable'); },
    tlsChecker: async () => { throw new Error('TLS unavailable'); }
  });
  assert.equal(failed.registration_error, 'RDAP unavailable');
  assert.equal(failed.tls_error, 'TLS unavailable');
  assert.equal(failed.registration_expires_at, now + 5 * 86400000);
  db.close();
});

test('external probe requires its own secret and only accepts matching hosts', async () => {
  const db = createDb();
  const env = { DB: db, API_SECRET: 'admin-secret', DOMAIN_PROBE_SECRET: 'a-long-independent-probe-secret' };
  await initDatabase(db);
  await initDomainDatabase(db);
  const id = crypto.randomUUID();
  await db.prepare(`INSERT INTO domain_monitors
    (id, domain, tls_host, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`)
    .bind(id, 'example.com', 'www.example.com', Date.now(), Date.now()).run();
  const endpoint = (path, method = 'GET', body = null, secret = env.DOMAIN_PROBE_SECRET) => new Request(`https://monitor.test${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${secret}`,
      ...(body ? { 'Content-Type': 'application/json' } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });

  assert.equal((await handleDomainProbeRequest(endpoint('/api/domain-probe/jobs', 'GET', null, 'wrong'), env)).status, 401);
  const jobs = await (await handleDomainProbeRequest(endpoint('/api/domain-probe/jobs'), env)).json();
  assert.deepEqual(jobs.jobs, [{ id, tls_host: 'www.example.com' }]);
  const expiresAt = Date.now() + 60 * 86400000;
  const badResult = await (await handleDomainProbeRequest(endpoint('/api/domain-probe/results', 'POST', {
    results: [{ id, tls_host: 'other.example.com', result: { expiresAt, authorized: true, hostnameValid: true } }]
  }), env)).json();
  assert.equal(badResult.accepted, 0);
  const goodResult = await (await handleDomainProbeRequest(endpoint('/api/domain-probe/results', 'POST', {
    results: [
      { id, tls_host: 'www.example.com', result: { expiresAt: 0, authorized: true, hostnameValid: true } },
      { id, tls_host: 'www.example.com', result: {
        expiresAt, notBefore: Date.now(), authorized: true, hostnameValid: true, issuer: 'CA', fingerprint: 'AA'
      } }
    ]
  }), env)).json();
  assert.equal(goodResult.accepted, 1);
  assert.equal((await db.prepare('SELECT tls_not_after FROM domain_monitors WHERE id = ?').bind(id).first()).tls_not_after, expiresAt);
  db.close();
});
