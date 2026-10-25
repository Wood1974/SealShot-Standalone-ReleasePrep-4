# SealShot standalone — iPhone validation gate

**Scope:** SealShot only. Never use Shield/TradeDeck/Tradeneck identifiers, repositories, credentials, storage, endpoints or app groups.

## Owner-only prerequisites

- Mac with current Xcode and XcodeGen; Apple Developer Team with access to signing.
- A unique, available **SealShot-only** bundle identifier. `com.sealshot.standalone` is a placeholder, not a reserved ID.
- A physical iPhone with a functioning Secure Enclave and camera.
- A **nonvaluable** test scene. This app has no recovery, cloud backup or trusted timestamp.

## Build

1. Extract the zip on a Mac and open Terminal inside `SealShot-Standalone-ReleasePrep`.
2. Install XcodeGen if needed, then run `xcodegen generate`.
3. Open `SealShot.xcodeproj`, choose the SealShot target, set an available SealShot-only bundle ID and your Apple Team.
4. Build for a physical iPhone. Record all compiler warnings/errors. **No iOS build has been run in this environment.**
5. Install on the iPhone. Approve the camera permission. Do not enable any Shield integrations.

## Minimum acceptance test (on iPhone)

- [ ] App launches and displays the **unverified** security labels.
- [ ] Camera permission denied -> explicit error, no evidence created.
- [ ] Camera permission granted -> live rear camera opens.
- [ ] Capture a **test** JPEG; app stores a `.sealshot` evidence file.
- [ ] Verify-and-view succeeds on the same device.
- [ ] Export evidence using share sheet; file contains encrypted data but **no content key**.
- [ ] Run `python verifier/verify_sealshot.py exported.sealshot` on an independent computer. Structure, signature, and ciphertext should be VALID; device attestation, capture time, camera origin and custody remain NOT_VERIFIED.
- [ ] Flip one byte in the exported ciphertext; verifier must show INVALID ciphertext integrity.
- [ ] Change a signed manifest field; verifier must show INVALID signature.
- [ ] Change the embedded public key; local view on original phone must reject it.
- [ ] Change the file name to another evidence ID; local view must reject it.
- [ ] Background/foreground and lock/unlock during capture; no crash or mislabeled evidence.
- [ ] Repeat capture 10 times; no UI freeze, duplicate capture or lost record.
- [ ] Test key-loss recovery scenario with **disposable evidence only**. There is no recovery path; do not delete the app with important data.

## Gate decisions

**Never claim** camera provenance, Apple attestation, trusted capture time, independent custody or durable retention from this local build. Never describe the app as production-ready or installable without successful Xcode compilation, signing, device tests and security review.

## Before TestFlight

- Confirm Apple bundle ID and signing are isolated from Shield.
- Complete real-device testing above.
- Add an explicit onboarding acknowledgment for unrecoverable key loss.
- Establish an approved recovery and backup design before collecting real evidence.
- Review camera queue concurrency under the exact Xcode/Swift toolchain; Linux cannot compile AVFoundation/UIKit/Security framework code.
- Complete independent security review and privacy documentation.
