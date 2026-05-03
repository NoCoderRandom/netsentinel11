# OUI data source and license notes (Prompt 14)

NetSentinel does not ship a hard-coded OUI database.

- The runtime OUI workflow expects users to provide a local CSV source.
- If cache is enabled, NetSentinel writes a local sanitized cache file for offline use after a successful import.
- Example sources for OUI data can be public IEEE registrations; review their license and redistribution terms before packaging or redistributing.
- This repository avoids bundling third-party or proprietary MAC-to-vendor data by default.
- Unknown or private addresses are reported as `Unknown Vendor` unless explicit policy disables unknown return.

