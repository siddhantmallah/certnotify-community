import { assertPublicHostname } from './ssrfGuard.js';
import type { UptimeResult, UptimeStatus } from '../types.js';

/**
 * Canonical uptime check. The original app had three divergent
 * implementations of this (a dedicated route, plus copies embedded in the
 * SSL route and the cron job) with different timeout values, different
 * status vocabularies, and no HTTP fallback in two of the three. This is
 * the consolidated version: HTTPS first, HTTP fallback, a 3-state
 * up/degraded/down status alongside the richer human-readable detail.
 */
export async function checkUptime(rawDomain: string, opts: { allowPrivate?: boolean } = {}): Promise<UptimeResult> {
  const domain = rawDomain.replace(/^https?:\/\//i, '').replace(/\/$/, '').split('/')[0].toLowerCase();

  await assertPublicHostname(domain, opts.allowPrivate);

  const start = Date.now();
  let statusCode = 0;
  let online = false;
  let finalUrl = '';
  let redirected = false;
  let protocol: 'https' | 'http' | 'unreachable' = 'unreachable';
  let server: string | null = null;
  let contentType: string | null = null;

  try {
    const res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      signal: AbortSignal.timeout(8000),
      redirect: 'follow',
    });
    statusCode = res.status;
    online = res.status < 500;
    finalUrl = res.url;
    redirected = res.url !== `https://${domain}` && res.url !== `https://${domain}/`;
    protocol = 'https';
    server = res.headers.get('server');
    contentType = res.headers.get('content-type');
  } catch {
    try {
      const res = await fetch(`http://${domain}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000),
        redirect: 'follow',
      });
      statusCode = res.status;
      online = res.status < 500;
      finalUrl = res.url;
      redirected = res.url !== `http://${domain}` && res.url !== `http://${domain}/`;
      protocol = 'http';
      server = res.headers.get('server');
    } catch {
      online = false;
    }
  }

  const responseTimeMs = Date.now() - start;

  const statusLabel =
    statusCode >= 500 ? 'Server Error'
      : statusCode >= 400 ? 'Client Error'
        : statusCode >= 300 ? 'Redirect'
          : statusCode >= 200 ? 'Online'
            : 'Unreachable';

  const performance =
    responseTimeMs < 300 ? 'Excellent'
      : responseTimeMs < 800 ? 'Good'
        : responseTimeMs < 2000 ? 'Fair'
          : 'Slow';

  const status: UptimeStatus = !online ? 'down' : statusCode >= 400 || responseTimeMs > 3000 ? 'degraded' : 'up';

  return {
    domain,
    status,
    online,
    statusCode,
    statusLabel,
    responseTimeMs,
    performance,
    protocol,
    finalUrl: finalUrl || null,
    redirected,
    server,
    contentType,
  };
}
