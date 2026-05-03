# Optional Agent Collector Protocol

Date: 2026-05-02

## Purpose

The optional agent collector protocol is for future Raspberry Pi, NAS, or second Windows device monitoring. This stage defines and validates the protocol shape with a mock collector only.

## Safety boundary

- Disabled by default.
- Mock-only in this stage.
- No agent service is installed.
- No background persistence is created.
- No sockets are opened by the mock collector.
- No public IPs are contacted.
- No exploit payloads, credential attacks, MITM, spoofing, deauth, stealth, or traffic disruption.

## Required production controls

- Mutual TLS for collector-to-agent authentication.
- Server certificate fingerprint or trust anchor pinning.
- Client certificate fingerprint or identity binding.
- Cryptographically signed pairing token.
- Least-privilege permissions such as `metrics:read` or `inventory:read`.
- Explicit install, start, stop, and removal flow.
- Clear user-facing logs for every lifecycle action.

## Pairing model

1. The desktop app creates a short-lived pairing token.
2. The token is signed by the local collector identity.
3. The agent presents its client certificate during mutual TLS.
4. The collector verifies the signed token, client certificate, permission scope, and user approval.
5. The agent is accepted only for the approved scopes.

## Non-goals

- No always-on hidden service.
- No silent persistence.
- No remote administration channel.
- No credential collection.
- No internet relay.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_api netsentinel_agent_collector_protocol_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "agent_collector_protocol_smoke|agent_collector_protocol_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe agent protocol --mock --output reports\agent_collector_prompt79.md
```
