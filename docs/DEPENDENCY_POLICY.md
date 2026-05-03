# Dependency policy (Prompt 02)

NetSentinel11 keeps dependencies optional by default unless explicitly enabled.

- Required dependencies: none
- Optional dependencies:
  - SQLite3 (`NETSENTINEL_ENABLE_SQLITE`)
  - spdlog (`NETSENTINEL_ENABLE_SPDLOG`)
  - nlohmann_json (`NETSENTINEL_ENABLE_JSON`)
  - GoogleTest (`NETSENTINEL_ENABLE_TEST_DEPENDENCIES`)

Runtime behavior if optional dependencies are unavailable:
- Build succeeds with warnings.
- CLI prints the current fallback matrix (`netsentinel11 --deps`).
- Missing modules stay in stub mode until enabled and installed.

