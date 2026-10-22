import { randomUUID } from 'node:crypto';

// A stand-in for an IdP's live session/SCIM state. No real credentials are used.
export class IdentityRegistry {
  #sessions = new Map();
  issue(subject = 'demo-user') {
    const token = randomUUID();
    this.#sessions.set(token, { subject, active: true, issuedAt: Date.now() });
    return token;
  }
  revoke(token) {
    const session = this.#sessions.get(token);
    if (!session) return false;
    session.active = false;
    return true;
  }
  assertActive(token) {
    const session = this.#sessions.get(token);
    if (!session?.active) {
      const err = new Error('Identity session inactive or revoked');
      err.code = 'IDENTITY_REVOKED';
      throw err;
    }
    return session.subject;
  }
}
