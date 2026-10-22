import { createHash } from 'node:crypto';

function canonical(obj) { return JSON.stringify(obj); }
function digest(value) { return createHash('sha256').update(value).digest('hex'); }

// Never accept arbitrary request bodies/headers in audit events.
export class AuditTrail {
  constructor() { this.events = []; }
  append({ action, outcome, reason = null, attempt = 0 }) {
    const previousHash = this.events.at(-1)?.hash ?? 'GENESIS';
    const entry = { sequence: this.events.length + 1, action, outcome, reason, attempt, previousHash };
    this.events.push({ ...entry, hash: digest(previousHash + canonical(entry)) });
  }
  verify() {
    return this.events.every((event, i) => {
      const previousHash = i ? this.events[i - 1].hash : 'GENESIS';
      const { hash, ...entry } = event;
      return event.previousHash === previousHash && hash === digest(previousHash + canonical(entry));
    });
  }
  toJSON() { return this.events.map(({...event}) => event); }
}
