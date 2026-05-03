# Release Checklist

- Build Release with MSVC/CMake.
- Run CTest smoke suite.
- Run hardening checkpoint.
- Verify installer packaging plan.
- Review privacy and threat model docs.
- Verify optional dependencies fail gracefully.
- Sign artifacts when signing credentials are available.
- Publish checksums and changelog.
- Verify uninstall preserves user data by default.
