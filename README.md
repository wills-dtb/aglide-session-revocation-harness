# Aglide — Session Revocation & Safe Replay Harness

**Independent engineering demonstration, not an Aglide integration, endorsement, or reproduction of proprietary internals.**

## Observed product problem

Aglide publicly describes securing non-SAML/legacy SaaS apps with IdP-driven access, an on-device browser agent, and zero-trust credentials. Its advertised founding engineering role stresses browser automation, debugging, reliability, and customer-facing problem ownership. An important class of failure in such systems is **IdP access revocation while a legacy app's session cookie remains live**. A separate risk is accidentally replaying a state-changing browser action after an ambiguous network failure.

This miniature harness explores two properties: **(1) live identity check before each tool operation; (2) only read-only operations receive automatic retries**. It uses a synthetic legacy HTTP app and does not access any real services or credentials.

## Assumptions

- The agent is trusted to call through the guard rather than directly through a browser/HTTP API.
- An IdP/SCIM-like system exposes a sufficiently fresh revocation signal.
- The legacy app does not itself know about the IdP and continues accepting its cookie after revocation.
- All protected actions are enumerated and assigned a read/mutation classification.
- Privileged actions require explicit approval; no automatic retries for writes.
- This is a **preflight gate**, not a complete security boundary or real browser extension.

## Architecture

```text
IdentityRegistry (IdP emulator) ----- revocation signal
                 |                           |
                 +------> AgentSessionGuard <+
                            |  policy allowlist / approvals
                            |  identity check per attempt
                            |  read-only retries / no write replay
                            |  structured redacted audit + hash chain
                            v
                      LegacyApp (HTTP fixture)
                      login cookie persists after IdP revocation
```

The guard intentionally never writes credentials or session cookies to audit records. The hash-chained audit catches accidental or naive modification of evidence, but is **not cryptographically authoritative** without remote anchoring and trusted storage.

## Run

Requires Node.js 20+. **No npm install or external services required.**

```bash
npm test          # 13 integration/unit tests
npm run demo      # local legacy app + login + read + revoke + deny
npm run check     # both
```

The demo binds an ephemeral HTTP port to `127.0.0.1`; it never calls external endpoints. It prints synthetic account data and sanitised audit events.

## Tests / engineering guarantees

1. Login and authorised read.
2. Revocation blocks access even when the legacy cookie remains valid.
3. Transient read retry.
4. Explicit approval for privileged actions.
5. Approved mutation.
6. No retry of mutation on ambiguous 503.
7. Unknown action denied.
8. Cross-origin destination denied.
9. Audit contains neither identity token nor legacy cookie.
10. Tampering with audit chain detected.
11. Revoked identity cannot initiate login.
12. Protected read requires login.
13. Revocation between retry attempts prevents a second request.

## Tradeoffs and what was deliberately left out (2–3 hour scope)

- No Playwright, Chromium, Electron, or real browser automation. A deterministic local HTTP fixture keeps the demo runnable without dependencies; real browser navigation and DOM state are future integration points.
- No real IdP, SAML, SCIM, encrypted vault, MFA, device trust, extension isolation, or browser cookie protection.
- No durable session store or distributed coordination.
- No concurrent revocation fencing: revocation **after** a preflight check but **before** the downstream side effect remains a time-of-check/time-of-use race.
- No signed approval tokens, user interaction, multi-tenant boundaries, or secret management.
- No comprehensive HTTP redirect/SSRF defense. Production allowlisting must check *actual* navigation and redirects, not just the intended destination.

## What production would need

- Real Playwright/extension adapter with enforced per-step policy, navigation interception and robust origin checking.
- Short-lived capabilities bound to tenant, user, device, app, action and IdP session version; revocation push plus periodic revalidation.
- Explicit server-side or browser-enforced fencing of privileged actions, with idempotency keys and reconciliation for uncertain writes.
- Device-bound credentials in a secure enclave/vault; never expose raw secrets to a general agent model.
- Signed, remotely anchored, privacy-preserving audit evidence with retention controls.
- Failure-injection/e2e tests for expired sessions, IdP outages, browser crashes, app DOM changes and partial completions.
- Tenant isolation, production telemetry, rollout flags, threat modelling and independent security review.

## Why this matters to Aglide

The aim is not to replace its product. It's a narrowly scoped demonstration of a failure mode adjacent to the public problem: **how to stop an already-authenticated legacy browser session from continuing agent work after identity revocation, without blindly retrying unsafe actions.** It is intended to start a technical conversation about operational invariants and real-world failure handling.

## Attribution

Built as an independent outreach exercise by William de Torvy-Ballou, October 2026. All services, identities and accounts in the demo are synthetic.
