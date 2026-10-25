# SealShot-only backend — design gate, not deployed

The standalone iPhone prototype has **no server** and must not contact Shield infrastructure.

## Isolation rules

1. Create a dedicated SealShot repository only after explicit user approval; never fork or merge Shield.
2. Use a SealShot-only API domain, database, storage bucket, secrets, service identity and Apple App Attest application identifier.
3. No imports, shared authentication, migrations, analytics, queues, app groups, tables or production credentials from Shield/TradeDeck/Tradeneck.
4. Tenant and owner identities must be signed into the evidence protocol; do not infer ownership from filenames or client flags.
5. Store ciphertext only. Never upload original JPEG or per-photo content keys to SealShot's server.
6. Before any retention promise, verify provider-enforced Object Lock COMPLIANCE mode and retention with a real provider read-back.
7. Server must independently verify Apple enrollment and per-capture assertions, enforce atomic replay counters, and sign acceptance receipts with an audited key-management plan.
8. Provide portable offline verification and independent timestamping; no claims beyond verified evidence.
9. Define recovery and succession policies before accepting irreplaceable evidence.

## Protocol integration warning

The standalone iOS prototype uses JSON `SealShot-Standalone-Local-v1`, while Stages 9–19 use an experimental CBOR protocol. **They are not wire-compatible.** Do not silently feed local JSON into the experimental backend. Design a versioned, reviewed migration or replace the local format with an agreed protocol before server acceptance.

## Approval gate

No provider, billing, infrastructure, network endpoints or account permissions have been selected. Require explicit owner approval before creating accounts, purchasing storage, provisioning Apple capabilities, or deploying.
