# Release Candidate Polish And Packaging

Date: 2026-05-02

## Scope

This stage prepares release-candidate readiness artifacts without installing services, drivers, firewall rules, or router integrations.

## Required disclosures

- Scans are only for networks the user owns or is explicitly authorized to test.
- Privacy-sensitive reports may contain device names, IPs, MACs, presence history, and bandwidth history.
- Npcap packet capture is optional and must never be installed silently.
- Router integrations are optional and must keep credentials local.
- Measurement limitations must be visible: per-device bandwidth can be estimated unless a trusted source is configured.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_installer netsentinel_release_candidate_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "release_candidate_smoke|release_candidate_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe release candidate --mock --npcap --router-integrations --output reports\release_candidate_prompt85.md --changelog reports\CHANGELOG_prompt85.md
```
