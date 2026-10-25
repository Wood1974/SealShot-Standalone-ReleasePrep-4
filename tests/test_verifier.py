import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verifier"))
from verify_sealshot import verify_bytes

DOMAIN = b"SealShot/standalone-local/v1\0"


def fixture():
    key = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    point = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    content_key = os.urandom(32)
    jpeg = b"\xff\xd8" + os.urandom(32) + b"\xff\xd9"
    evidence_id = "example-0001"
    nonce = os.urandom(12)
    encrypted = AESGCM(content_key).encrypt(nonce, jpeg, b"SealShot/local-photo/v1/" + evidence_id.encode())
    manifest = {
        "protocolVersion": 1, "evidenceID": evidence_id,
        "ownerID": "test-owner", "jobLabel": "test",
        "originalSHA256": hashlib.sha256(jpeg).hexdigest(),
        "originalLength": len(jpeg),
        "ciphertextSHA256": hashlib.sha256(encrypted).hexdigest(),
        "nonceBase64": base64.b64encode(nonce).decode(),
        "captureMethod": "AVFoundation-live-camera-client-asserted",
        "deviceClaimedAt": "2026-10-25T10:00:00Z",
        "timeAssurance": "DEVICE_CLOCK_UNVERIFIED",
        "attestationAssurance": "NOT_VERIFIED",
        "signingAssurance": "LOCAL_SECURE_ENCLAVE_KEY_UNENROLLED",
    }
    m = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(DOMAIN + m, ec.ECDSA(hashes.SHA256()))
    def b(x): return base64.b64encode(x).decode()
    env = {
        "format": "SealShot-Standalone-Local-v1",
        "manifestBase64": b(m), "signatureBase64": b(sig),
        "publicKeyX963Base64": b(point), "nonceBase64": b(nonce),
        "ciphertextAndTagBase64": b(encrypted),
    }
    return env, content_key


def raw(env): return json.dumps(env, separators=(",", ":")).encode()


def test_valid_signatures_and_decryption():
    env, key = fixture()
    report = verify_bytes(raw(env), content_key=key)
    assert report["manifest_signature"] == "VALID"
    assert report["ciphertext_integrity"] == "VALID"
    assert report["original_integrity"] == "VALID"
    assert report["device_attestation"] == "NOT_VERIFIED"


def test_ciphertext_tamper():
    env, key = fixture()
    changed = bytearray(base64.b64decode(env["ciphertextAndTagBase64"]))
    changed[0] ^= 1
    env["ciphertextAndTagBase64"] = base64.b64encode(changed).decode()
    report = verify_bytes(raw(env), content_key=key)
    assert report["ciphertext_integrity"] == "INVALID"
    assert report["original_integrity"] == "NOT_CHECKED"


def test_signature_tamper():
    env, _ = fixture()
    sig = bytearray(base64.b64decode(env["signatureBase64"]))
    sig[-1] ^= 1
    env["signatureBase64"] = base64.b64encode(sig).decode()
    assert verify_bytes(raw(env))["manifest_signature"] == "INVALID"


def test_manifest_tamper():
    env, _ = fixture()
    manifest = json.loads(base64.b64decode(env["manifestBase64"]))
    manifest["jobLabel"] = "changed"
    env["manifestBase64"] = base64.b64encode(json.dumps(manifest).encode()).decode()
    assert verify_bytes(raw(env))["manifest_signature"] == "INVALID"


def test_wrong_content_key_preserves_signature():
    env, _ = fixture()
    report = verify_bytes(raw(env), content_key=os.urandom(32))
    assert report["manifest_signature"] == "VALID"
    assert report["original_integrity"] == "INVALID"


def test_untrusted_key_is_not_authorization():
    env, _ = fixture()
    report = verify_bytes(raw(env))
    assert report["signer_authorization"] == "NOT_VERIFIED"
    assert report["camera_origin"] == "NOT_VERIFIED"


def test_reject_unrecognized_claim():
    env, _ = fixture()
    manifest = json.loads(base64.b64decode(env["manifestBase64"]))
    manifest["attestationAssurance"] = "ATTESTED"
    env["manifestBase64"] = base64.b64encode(json.dumps(manifest).encode()).decode()
    assert verify_bytes(raw(env))["structure"] == "INVALID"


def test_reject_malformed_json():
    assert verify_bytes(b"not json")["structure"] == "INVALID"


def test_no_shield_project_dependencies():
    root = Path(__file__).resolve().parents[1]
    source = "\n".join(p.read_text() for p in (root / "SealShotApp").rglob("*.swift"))
    assert "import Shield" not in source
    assert "tradedeck" not in source.lower()
    assert "tradeneck" not in source.lower()


def test_nonce_substitution_detected():
    env, _ = fixture()
    env["nonceBase64"] = base64.b64encode(os.urandom(12)).decode()
    assert verify_bytes(raw(env))["structure"] == "INVALID"
