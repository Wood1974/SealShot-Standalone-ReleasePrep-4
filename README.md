# SealShot — completely standalone iPhone app source

**Separate app, separate bundle identifier, separate storage, separate signing keys, separate codebase. No Shield, Tradedeck, or Tradeneck dependency or integration.**

## Current scope

This is a **standalone offline iOS source project**, not a signed/compiled IPA or App Store release. It provides:

- SwiftUI interface and live AVFoundation rear-camera JPEG capture (no photo-library import).
- P-256 Secure Enclave signing key, unique to the SealShot app's Keychain namespace.
- Fresh per-photo AES-256-GCM encryption key, stored in SealShot's own ThisDeviceOnly Keychain namespace.
- Local encrypted `.sealshot` evidence records with signed exact-byte hashes, encrypted photo, and untrusted public signing point.
- Local verify-and-view (requires original device and its local content key).
- Export encrypted evidence via the iOS share sheet, **without exporting its content key**.
- Independent Python offline verifier for signatures, hashes, and optional original-byte decryption when a key is explicitly supplied by an authorized person.

**Not implemented:** account sign-in, cloud server, independent device enrollment, Apple App Attest verification, RFC3161, WORM cloud storage, signed custody anchors, recipient grants, recovery, trusted capture time, and production key rotation. Nothing here proves actual camera exposure or Apple enrollment. These claims must remain NOT_VERIFIED.

**Important: data-loss risk.** Per-photo content keys are ThisDeviceOnly and there is no recovery flow. Deleting the app, losing the device, or losing its Keychain material may permanently prevent decryption. Do not use this experimental build as your only record of valuable evidence.

## Build on Mac (owner-only)

1. Install Xcode and XcodeGen (`brew install xcodegen`).
2. In this directory run `xcodegen generate` to produce `SealShot.xcodeproj`.
3. Open project in Xcode. Select your own Apple Development Team and change `com.sealshot.standalone` to an available **SealShot-only** bundle ID.
4. Choose a real iPhone with Secure Enclave, approve camera permission, then build/run. The simulator is not a substitute for Secure Enclave testing.
5. Test capture, verify-and-view, export, and evidence tampering. No server is required.

No Apple signing certificates, entitlements, TestFlight setup, or device provisioning are included. Swift source has **not been compiled or tested on a Mac/iPhone** in this environment.

## Run offline verifier

```bash
python -m pip install -r requirements.txt
python -m pytest -q tests
python verifier/verify_sealshot.py path/to/exported-file.sealshot
```

The verifier checks the signature using the public key embedded in the bundle. This establishes mathematical consistency, **not independent identity authorization**. It will not claim device attestation, camera provenance, trusted capture time, or custody.

## Architectural isolation

- App name: `SealShot`.
- Bundle ID (placeholder): `com.sealshot.standalone`.
- Local key namespaces: `com.sealshot.standalone.*`.
- Local vault: app sandbox `Documents/Evidence`.
- No network endpoints, external accounts, SDKs, analytics, or Shield source imports.
- This package does not modify, migrate, import, link, or merge with any existing Shield repository or service.

## Security and quality caveats

The Swift app is a reference implementation and needs Mac/iPhone compilation and lifecycle tests, secure backup/recovery design, stronger export format and parser bounds, account identity model, file-protection testing, and independent security review. Do not treat the device clock as independently verified. A locally signed manifest alone cannot establish camera provenance. The JSON evidence format is **SealShot-Standalone-Local-v1**, not wire-compatible with the earlier Stage 9–19 CBOR reference; protocol reconciliation and interoperability must be completed before production server acceptance.

## Release-preparation update

This package includes additional **local-only** hardening:

- Local view requires the exported signing point to match the current app's own Secure Enclave signing key; it does not trust an arbitrary embedded public key.
- Local vault checks the signed evidence ID against its filename and checks the signed owner ID against the current local owner.
- Camera session start/stop is scheduled on a dedicated serial queue rather than synchronously blocking the main UI thread. Swift/iOS compilation is still required to validate concurrency behavior.
- Independent Python verifier rejects duplicate JSON keys and imposes tighter bounds on key fields. It accepts an optional externally obtained public point for **KEY_MATCH_ONLY**, not verified authorization.
- Added regression tests and a real-iPhone validation checklist under `release/`.

**No Swift build, physical iPhone run, Apple enrollment, recovery or cloud integration has occurred.** The standalone local JSON protocol is not wire-compatible with the experimental Stage 9–19 CBOR format.
