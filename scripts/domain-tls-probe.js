#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { checkTlsCertificate } from '../src/domain-monitor/checks.js';

const REQUEST_TIMEOUT_MS = 20000;

async function request(url, secret, init = {}) {
  const response = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${secret}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {})
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`Domain probe API returned ${response.status}`);
  return response.json();
}

export async function runDomainTlsProbe(options = {}) {
  const base = String(options.baseUrl || process.env.DOMAIN_PROBE_URL || '').replace(/\/$/, '');
  const secret = String(options.secret || process.env.DOMAIN_PROBE_SECRET || '');
  if (!/^https:\/\//.test(base) && !/^http:\/\/localhost(?::\d+)?$/.test(base)) {
    throw new Error('DOMAIN_PROBE_URL must be an HTTPS origin');
  }
  if (secret.length < 16) throw new Error('DOMAIN_PROBE_SECRET must contain at least 16 characters');

  const jobs = [];
  let cursor = '';
  do {
    const page = await request(`${base}/api/domain-probe/jobs${cursor ? `?after=${encodeURIComponent(cursor)}` : ''}`, secret);
    jobs.push(...page.jobs);
    cursor = page.next_cursor || '';
  } while (cursor);

  let accepted = 0;
  for (let index = 0; index < jobs.length; index += 20) {
    const batch = jobs.slice(index, index + 20);
    const results = [];
    for (let offset = 0; offset < batch.length; offset += 4) {
      const group = batch.slice(offset, offset + 4);
      results.push(...await Promise.all(group.map(async job => {
        try {
          return {
            id: job.id,
            tls_host: job.tls_host,
            result: await checkTlsCertificate(job.tls_host, { allowInvalid: true })
          };
        } catch (error) {
          return {
            id: job.id,
            tls_host: job.tls_host,
            result: { error: String(error?.message || error).slice(0, 300) }
          };
        }
      })));
    }
    const response = await request(`${base}/api/domain-probe/results`, secret, {
      method: 'POST',
      body: JSON.stringify({ results })
    });
    accepted += response.accepted;
  }
  return { checked: jobs.length, accepted };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  runDomainTlsProbe().then(result => {
    console.log(`Checked ${result.checked} TLS hosts; accepted ${result.accepted} results.`);
  }).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
