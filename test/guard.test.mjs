import test from 'node:test';
import assert from 'node:assert/strict';
import { IdentityRegistry } from '../src/identity.mjs';
import { AgentSessionGuard } from '../src/guard.mjs';
import { startLegacyApp } from '../src/legacy-app.mjs';

async function setup(t, opts = {}) {
  const app = await startLegacyApp();
  t.after(() => app.close());
  const identity = new IdentityRegistry();
  const token = identity.issue();
  const guard = new AgentSessionGuard({ origin: app.origin, identity, token, ...opts });
  return { app, identity, token, guard };
}

test('login and safe read succeeds', async t => {
  const { guard } = await setup(t);
  await guard.execute('login');
  assert.equal((await guard.execute('account')).balance, 42);
  assert.equal(guard.audit.verify(), true);
});

test('IdP revocation blocks subsequent action even when legacy cookie remains valid', async t => {
  const { guard, identity, token, app } = await setup(t);
  await guard.execute('login');
  identity.revoke(token);
  await assert.rejects(guard.execute('account'), { code: 'IDENTITY_REVOKED' });
  assert.equal(app.state.reads, 0);
  assert.ok(guard.cookie);
});

test('read-only operation retries transient 503 once', async t => {
  const { guard, app } = await setup(t);
  await guard.execute('login');
  app.state.transientReadFailures = 1;
  assert.equal((await guard.execute('account')).balance, 42);
  assert.equal(app.state.reads, 2);
  assert.equal(guard.audit.events.some(e => e.outcome === 'retry'), true);
});

test('privileged mutation requires explicit approval', async t => {
  const { guard, app } = await setup(t);
  await guard.execute('login');
  await assert.rejects(guard.execute('settings'), { code: 'APPROVAL_REQUIRED' });
  assert.equal(app.state.mutations, 0);
});

test('approved mutation succeeds once', async t => {
  const { guard, app } = await setup(t, { approvedActions: ['settings'] });
  await guard.execute('login');
  assert.equal((await guard.execute('settings')).updated, true);
  assert.equal(app.state.mutations, 1);
});

test('mutation never automatically retries a transient 503', async t => {
  const { guard, app } = await setup(t, { approvedActions: ['settings'] });
  await guard.execute('login');
  app.state.transientMutationFailures = 1;
  await assert.rejects(guard.execute('settings'), { code: 'HTTP_503' });
  assert.equal(app.state.mutations, 1);
});

test('unknown operation rejected before any request', async t => {
  const { guard } = await setup(t);
  await assert.rejects(guard.execute('deleteAll'), { code: 'UNKNOWN_ACTION' });
});

test('cross-origin request rejected', async t => {
  const { guard } = await setup(t);
  await assert.rejects(guard.execute('account', { destination: 'https://attacker.invalid' }), { code: 'CROSS_ORIGIN' });
});

test('audit records no bearer token or legacy cookie', async t => {
  const { guard, token } = await setup(t);
  await guard.execute('login');
  await guard.execute('account');
  const audit = JSON.stringify(guard.audit.toJSON());
  assert.equal(audit.includes(token), false);
  assert.equal(audit.includes(guard.cookie), false);
  assert.equal(audit.includes('legacy_session='), false);
});

test('audit tampering detected', async t => {
  const { guard } = await setup(t);
  await guard.execute('login');
  assert.equal(guard.audit.verify(), true);
  guard.audit.events[0].outcome = 'denied';
  assert.equal(guard.audit.verify(), false);
});

test('revoked identity cannot bootstrap a legacy session', async t => {
  const { guard, token, identity } = await setup(t);
  identity.revoke(token);
  await assert.rejects(guard.execute('login'), { code: 'IDENTITY_REVOKED' });
  assert.equal(guard.cookie, null);
});

test('read before login fails safely', async t => {
  const { guard } = await setup(t);
  await assert.rejects(guard.execute('account'), { code: 'NO_LEGACY_SESSION' });
});

test('revocation during retry prevents second request', async t => {
  const { guard, app, token, identity } = await setup(t);
  await guard.execute('login');
  app.state.transientReadFailures = 1;
  const original = guard.transport;
  guard.transport = async (...args) => {
    const response = await original(...args);
    if (response.status === 503) identity.revoke(token);
    return response;
  };
  await assert.rejects(guard.execute('account'), { code: 'IDENTITY_REVOKED' });
  assert.equal(app.state.reads, 1);
});
