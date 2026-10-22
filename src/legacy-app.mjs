import http from 'node:http';
import { randomUUID } from 'node:crypto';

// Simulates a non-SAML legacy SaaS app that knows nothing about IdP revocation.
export async function startLegacyApp() {
  const sessions = new Set();
  const state = { reads: 0, mutations: 0, transientReadFailures: 0, transientMutationFailures: 0 };
  const server = http.createServer(async (req, res) => {
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(JSON.stringify(body));
    };
    if (req.url === '/login' && req.method === 'POST') {
      const cookie = randomUUID();
      sessions.add(cookie);
      return send(200, { ok: true }, { 'set-cookie': `legacy_session=${cookie}; HttpOnly; SameSite=Strict` });
    }
    const cookie = /(?:^|;\s*)legacy_session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    if (!cookie || !sessions.has(cookie)) return send(401, { error: 'unauthorized' });
    if (req.url === '/account' && req.method === 'GET') {
      state.reads++;
      if (state.transientReadFailures-- > 0) return send(503, { error: 'temporarily_unavailable' });
      return send(200, { account: 'synthetic-demo', balance: 42 });
    }
    if (req.url === '/settings' && req.method === 'POST') {
      state.mutations++;
      if (state.transientMutationFailures-- > 0) return send(503, { error: 'temporarily_unavailable' });
      return send(200, { updated: true });
    }
    return send(404, { error: 'not_found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    state,
    close: () => new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()))
  };
}
