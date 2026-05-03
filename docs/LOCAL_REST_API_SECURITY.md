# Local REST API security model

Date: 2026-05-02

## Scope

The local REST API is a future companion interface for the Windows desktop app. It is not an internet-facing service and must stay disabled unless the user explicitly enables it.

## Required controls

- Disabled by default.
- Binds only to `127.0.0.1`, `localhost`, or `::1`.
- Requires bearer-token authentication when enabled.
- Uses endpoint permission scopes such as `read` and `scan:trigger`.
- Requires a CSRF token for state-changing requests.
- Applies a local request-rate guard.
- Keeps scan trigger dry-run by default until a local service owns safe orchestration.
- Must not open firewall ports or bind to `0.0.0.0` for pairing.

## Current permission model

- `read`: allows read-only endpoints such as `/v1/networks`, `/v1/devices`, `/v1/scans`, `/v1/events`, `/v1/findings`, `/v1/speed-tests`, and `/v1/pairing/guide`.
- `scan:trigger`: allows `/v1/scans/trigger` only when token auth, rate limit, and CSRF checks also pass.
- `admin`: reserved local-only super-scope for future desktop-controlled workflows.

## Safe future companion pairing

A future companion should pair through the desktop app, not by exposing the API to the LAN or internet.

Recommended flow:

1. The desktop app shows a one-time local pairing code.
2. The companion exchange happens only through `localhost`.
3. The desktop app creates a short-lived scoped token.
4. The companion stores only the scoped token locally.
5. State-changing calls require both bearer token and CSRF token.
6. The API remains bound to loopback and no firewall rule is added.

## Explicit non-goals

- No public-IP exposure.
- No LAN-wide REST listener.
- No default token.
- No credential brute force or exploit payloads.
- No MITM, spoofing, deauth, or stealth behavior.

## Validation commands

```powershell
build\bin\Debug\netsentinel11.exe api status --enabled --token local-test-token --csrf local-csrf --permission read --permission scan:trigger --rate-limit 60
build\bin\Debug\netsentinel11.exe api request --enabled --token local-test-token --path /v1/pairing/guide --permission read
build\bin\Debug\netsentinel11.exe api request --enabled --token local-test-token --path /v1/scans/trigger --method POST --permission scan:trigger --csrf local-csrf --request-csrf local-csrf
```
