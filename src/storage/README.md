# storage

Storage abstraction layer for scan persistence and migration history.

- Prompt 12 (SQLite storage foundation) scaffold:
  - Storage config and schema migration entry points
  - File-backed schema tracker (`SCHEMA_VERSION` + table-like line records)
  - Persisting scan sessions and probe lines to an append-only storage file
  - Load and export scan sessions as JSON
  - Migration guard for schema upgrades and safer fallback when optional dependencies are unavailable

This module is implemented as a safe, file-backed foundation that can be replaced
with full SQLite bindings in environments where native DB APIs are available.
