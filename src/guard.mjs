import { AuditTrail } from './audit.mjs';

const OPERATIONS = Object.freeze({
  login: { method: 'POST', path: '/login', kind: 'bootstrap' },
  account: { method: 'GET', path: '/account', kind: 'read' },
  settings: { method: 'POST', path: '/settings', kind: 'mutation' }
});

function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class AgentSessionGuard {
  constructor({ origin, identity, token, approvedActions = [], maxReadRetries = 1, transport = fetch }) {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw failure('BAD_ORIGIN', 'Invalid protocol');
    this.origin = parsed.origin;
    this.identity = identity;
    this.token = token;
    this.approvedActions = new Set(approvedActions);
    this.maxReadRetries = maxReadRetries;
    this.transport = transport;
    this.cookie = null;
    this.audit = new AuditTrail();
  }

  async execute(action, { destination = null } = {}) {
    const spec = OPERATIONS[action];
    if (!spec) {
      this.audit.append({ action: String(action), outcome: 'denied', reason: 'UNKNOWN_ACTION' });
      throw failure('UNKNOWN_ACTION', 'Operation is not in the allowlist');
    }
    if (destination && new URL(destination).origin !== this.origin) {
      this.audit.append({ action, outcome: 'denied', reason: 'CROSS_ORIGIN' });
      throw failure('CROSS_ORIGIN', 'Cross-origin navigation denied');
    }
    if (spec.kind === 'mutation' && !this.approvedActions.has(action)) {
      this.audit.append({ action, outcome: 'denied', reason: 'APPROVAL_REQUIRED' });
      throw failure('APPROVAL_REQUIRED', 'Privileged operation requires approval');
    }
    const attempts = spec.kind === 'read' ? this.maxReadRetries + 1 : 1;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      // Live check before EVERY attempt: a revoked identity must not keep using a live legacy cookie.
      try { this.identity.assertActive(this.token); }
      catch (err) {
        this.audit.append({ action, outcome: 'denied', reason: 'IDENTITY_REVOKED', attempt });
        throw err;
      }
      if (action !== 'login' && !this.cookie) {
        this.audit.append({ action, outcome: 'denied', reason: 'NO_LEGACY_SESSION', attempt });
        throw failure('NO_LEGACY_SESSION', 'Login must precede protected operations');
      }
      let response;
      try {
        response = await this.transport(new URL(spec.path, this.origin), {
          method: spec.method,
          headers: this.cookie ? { cookie: this.cookie } : {},
          redirect: 'manual',
          signal: AbortSignal.timeout(1500)
        });
      } catch {
        this.audit.append({ action, outcome: 'failed', reason: 'NETWORK_ERROR', attempt });
        if (attempt < attempts) continue;
        throw failure('NETWORK_ERROR', 'Request failed; no unsafe automatic retry');
      }
      if (response.status === 503 && attempt < attempts) {
        this.audit.append({ action, outcome: 'retry', reason: 'TRANSIENT_503', attempt });
        continue;
      }
      if (!response.ok) {
        this.audit.append({ action, outcome: 'failed', reason: `HTTP_${response.status}`, attempt });
        throw failure(`HTTP_${response.status}`, `Legacy app responded ${response.status}`);
      }
      if (action === 'login') {
        const setCookie = response.headers.get('set-cookie');
        const value = /legacy_session=([^;]+)/.exec(setCookie ?? '')?.[1];
        if (!value) throw failure('BAD_COOKIE', 'Legacy app returned no session');
        this.cookie = `legacy_session=${value}`;
      }
      this.audit.append({ action, outcome: 'success', attempt });
      return response.json();
    }
  }
}
