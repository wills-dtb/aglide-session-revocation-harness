import { IdentityRegistry } from '../src/identity.mjs';
import { AgentSessionGuard } from '../src/guard.mjs';
import { startLegacyApp } from '../src/legacy-app.mjs';

const app = await startLegacyApp();
try {
  const identity = new IdentityRegistry();
  const token = identity.issue();
  const agent = new AgentSessionGuard({ origin: app.origin, identity, token });
  await agent.execute('login');
  console.log('Account read:', await agent.execute('account'));
  identity.revoke(token);
  try { await agent.execute('account'); }
  catch (err) { console.log('After IdP revocation:', err.code); }
  console.log('Legacy cookie still exists:', Boolean(agent.cookie));
  console.log('Audit integrity:', agent.audit.verify());
  console.log('Sanitised audit:', JSON.stringify(agent.audit.toJSON(), null, 2));
} finally { await app.close(); }
