import { connect, checkServerIdentity } from 'node:tls';

const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const REQUEST_TIMEOUT_MS = 10000;
let bootstrapCache = null;
let bootstrapPending = null;

export function normalizeDomainName(value) {
  const input = String(value || '').trim().replace(/\.$/, '').toLowerCase();
  if (!input || /[\s/@:#?\\]/.test(input)) return null;

  let name;
  try {
    name = new URL(`https://${input}`).hostname;
  } catch (_) {
    return null;
  }

  if (name.length > 253 || name !== input && !/[\u0080-\uffff]/.test(input)) return null;
  const labels = name.split('.');
  if (labels.length < 2 || !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(labels.at(-1))) return null;
  if (labels.some(label => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    return null;
  }
  return name;
}

export function normalizeDomainInput(input) {
  const domain = normalizeDomainName(input?.domain);
  const tlsHost = normalizeDomainName(input?.tls_host || input?.domain);
  const reminderDays = Number(input?.reminder_days ?? 30);
  const label = String(input?.label || '').trim();

  if (!domain || !tlsHost || (tlsHost !== domain && !tlsHost.endsWith(`.${domain}`))) {
    throw new Error('Enter a registered domain and a TLS host within that domain');
  }
  if (!Number.isInteger(reminderDays) || reminderDays < 1 || reminderDays > 90) {
    throw new Error('Reminder days must be an integer from 1 to 90');
  }
  if (label.length > 100) throw new Error('Label is too long');

  return {
    domain,
    tls_host: tlsHost,
    label,
    reminder_days: reminderDays,
    enabled: [false, 0, 'false', '0'].includes(input?.enabled) ? 0 : 1
  };
}

async function getRdapBootstrap(fetcher, now) {
  if (bootstrapCache && now - bootstrapCache.fetchedAt < 24 * 60 * 60 * 1000) {
    return bootstrapCache.services;
  }
  if (!bootstrapPending) {
    bootstrapPending = (async () => {
      const response = await fetcher(RDAP_BOOTSTRAP_URL, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (!response.ok) throw new Error(`RDAP bootstrap returned ${response.status}`);
      const document = await response.json();
      if (!Array.isArray(document.services)) throw new Error('Invalid RDAP bootstrap data');
      bootstrapCache = { services: document.services, fetchedAt: now };
      return document.services;
    })().finally(() => { bootstrapPending = null; });
  }
  return bootstrapPending;
}

export function parseRdapExpiration(document) {
  const events = Array.isArray(document?.events) ? document.events : [];
  const expiry = events.find(event => /^(expiration|expiry|registry expiration)$/i.test(String(event?.eventAction || '')));
  const timestamp = Date.parse(expiry?.eventDate || '');
  return Number.isFinite(timestamp) ? timestamp : null;
}

export async function checkRegistration(domain, options = {}) {
  const fetcher = options.fetcher || fetch;
  const now = options.now || Date.now();
  const services = await getRdapBootstrap(fetcher, now);
  const tld = domain.split('.').at(-1);
  const entry = services.find(([suffixes]) => suffixes.some(suffix => String(suffix).toLowerCase() === tld));
  const base = entry?.[1]?.find(url => String(url).startsWith('https://'));
  if (!base) throw new Error(`No HTTPS RDAP service for .${tld}`);

  const source = `${base.replace(/\/*$/, '/')}domain/${encodeURIComponent(domain)}`;
  const response = await fetcher(source, {
    headers: { Accept: 'application/rdap+json' },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`RDAP lookup returned ${response.status}`);
  const document = await response.json();
  const expiresAt = parseRdapExpiration(document);
  if (expiresAt === null) throw new Error('RDAP did not provide an expiration date');
  return { expiresAt, source };
}

export function checkTlsCertificate(host, options = {}) {
  const connector = options.connector || connect;
  return new Promise((resolve, reject) => {
    let socket;
    let settled = false;
    const timer = setTimeout(() => finish(new Error('TLS connection timed out')), REQUEST_TIMEOUT_MS);
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket) socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };

    try {
      const connectionOptions = {
        host,
        port: 443,
        servername: host,
        timeout: REQUEST_TIMEOUT_MS
      };
      if (options.allowInvalid) connectionOptions.rejectUnauthorized = false;
      socket = connector(connectionOptions);
      socket.once('timeout', () => finish(new Error('TLS connection timed out')));
      socket.once('error', error => finish(error));
      socket.once('secureConnect', () => {
        if (typeof socket.getPeerCertificate !== 'function') {
          finish(new Error('TLS peer certificate inspection is unavailable in this runtime'));
          return;
        }
        const certificate = socket.getPeerCertificate();
        const expiresAt = Date.parse(certificate?.valid_to || '');
        if (!Number.isFinite(expiresAt)) {
          finish(new Error('TLS peer did not provide a readable certificate expiration date'));
          return;
        }
        const hostnameError = checkServerIdentity(host, certificate);
        finish(null, {
          expiresAt,
          notBefore: Number.isFinite(Date.parse(certificate.valid_from || '')) ? Date.parse(certificate.valid_from) : null,
          authorized: socket.authorized === true,
          hostnameValid: !hostnameError,
          validationError: String(hostnameError?.message || socket.authorizationError || ''),
          issuer: String(certificate.issuer?.CN || '').slice(0, 200),
          fingerprint: String(certificate.fingerprint256 || '').slice(0, 100)
        });
      });
    } catch (error) {
      finish(error);
    }
  });
}

export function alertTier(expiresAt, reminderDays, now = Date.now()) {
  if (expiresAt === null || !Number.isFinite(expiresAt)) return null;
  const days = Math.ceil((expiresAt - now) / 86400000);
  if (days > reminderDays) return null;
  const tiers = [...new Set([reminderDays, 30, 14, 7, 3, 1, 0])]
    .filter(tier => tier <= reminderDays)
    .sort((a, b) => b - a);
  return { days, tier: tiers.filter(value => days <= value).at(-1) ?? 0 };
}

export function clearRdapBootstrapCache() {
  bootstrapCache = null;
  bootstrapPending = null;
}
