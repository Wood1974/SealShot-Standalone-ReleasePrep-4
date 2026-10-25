#!/usr/bin/env python3
"""Independent offline verifier for SealShot Standalone Local v1.

Checks signature and ciphertext binding. Embedded public key is NOT an
independent identity or Apple App Attest trust anchor.

Usage: python verifier/verify_sealshot.py evidence.sealshot
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b"SealShot/standalone-local/v1\0"
AAD_PREFIX = b"SealShot/local-photo/v1/"
MAX_BYTES = 150 * 1024 * 1024


def _decode(value):
    if not isinstance(value, str):
        raise ValueError("Base64 field must be text")
    return base64.b64decode(value, validate=True)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _load_json(raw):
    # Reject duplicate keys rather than letting an attacker exploit
    # disagreement between parsers about which value is authoritative.
    return json.loads(raw, object_pairs_hook=_unique_object)


def verify_bytes(raw, *, content_key=None, trusted_public_point=None):
    result = {
        "format": "SealShot-Standalone-Local-v1",
        "structure": "INVALID",
        "manifest_signature": "NOT_CHECKED",
        "ciphertext_integrity": "NOT_CHECKED",
        "original_integrity": "NOT_CHECKED",
        "signer_authorization": "NOT_VERIFIED",
        "camera_origin": "NOT_VERIFIED",
        "device_attestation": "NOT_VERIFIED",
        "capture_time": "DEVICE_CLOCK_UNVERIFIED",
        "independent_timestamp": "NOT_VERIFIED",
        "custody": "NOT_VERIFIED",
    }
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise ValueError("Oversized evidence")
        obj = _load_json(raw)
        expected = {"format", "manifestBase64", "signatureBase64", "publicKeyX963Base64", "nonceBase64", "ciphertextAndTagBase64"}
        if not isinstance(obj, dict) or set(obj) != expected or obj["format"] != result["format"]:
            raise ValueError("Invalid envelope")
        manifest_bytes = _decode(obj["manifestBase64"])
        signature = _decode(obj["signatureBase64"])
        point = _decode(obj["publicKeyX963Base64"])
        nonce = _decode(obj["nonceBase64"])
        ciphertext = _decode(obj["ciphertextAndTagBase64"])
        if len(manifest_bytes) > 65536 or len(nonce) != 12 or len(ciphertext) < 16 or len(point) != 65:
            raise ValueError("Invalid record sizes")
        manifest = _load_json(manifest_bytes)
        fields = {"protocolVersion", "evidenceID", "ownerID", "jobLabel", "originalSHA256", "originalLength", "ciphertextSHA256", "nonceBase64", "captureMethod", "deviceClaimedAt", "timeAssurance", "attestationAssurance", "signingAssurance"}
        if not isinstance(manifest, dict) or set(manifest) != fields or type(manifest["protocolVersion"]) is not int or manifest["protocolVersion"] != 1:
            raise ValueError("Unsupported manifest")
        if manifest["captureMethod"] != "AVFoundation-live-camera-client-asserted" or manifest["timeAssurance"] != "DEVICE_CLOCK_UNVERIFIED" or manifest["attestationAssurance"] != "NOT_VERIFIED" or manifest["signingAssurance"] != "LOCAL_SECURE_ENCLAVE_KEY_UNENROLLED":
            raise ValueError("Unsupported assurance claims")
        if manifest["nonceBase64"] != obj["nonceBase64"]:
            raise ValueError("Nonce does not match signed manifest")
        if not all(isinstance(manifest[k], str) and 0 < len(manifest[k]) <= 256 for k in ("evidenceID", "ownerID", "deviceClaimedAt")):
            raise ValueError("Invalid identity")
        if not isinstance(manifest["jobLabel"], str) or len(manifest["jobLabel"]) > 128 or type(manifest["originalLength"]) is not int or not (1 <= manifest["originalLength"] <= 100 * 1024 * 1024):
            raise ValueError("Invalid fields")
        if not all(isinstance(manifest[k], str) and len(manifest[k]) == 64 and all(c in "0123456789abcdef" for c in manifest[k]) for k in ("originalSHA256", "ciphertextSHA256")):
            raise ValueError("Invalid digests")
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        result["structure"] = "VALID"
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return result

    try:
        public_key.verify(signature, DOMAIN + manifest_bytes, ec.ECDSA(hashes.SHA256()))
        result["manifest_signature"] = "VALID"
    except (InvalidSignature, ValueError, TypeError):
        result["manifest_signature"] = "INVALID"

    result["ciphertext_integrity"] = (
        "VALID" if hashlib.sha256(ciphertext).hexdigest() == manifest["ciphertextSHA256"] else "INVALID"
    )
    if trusted_public_point is not None:
        result["signer_authorization"] = (
            "KEY_MATCH_ONLY" if trusted_public_point == point else "INVALID"
        )
    if content_key is not None:
        if not isinstance(content_key, bytes) or len(content_key) != 32:
            result["original_integrity"] = "INVALID"
        elif result["ciphertext_integrity"] != "VALID":
            result["original_integrity"] = "NOT_CHECKED"
        else:
            try:
                original = AESGCM(content_key).decrypt(
                    nonce, ciphertext, AAD_PREFIX + manifest["evidenceID"].encode("utf-8")
                )
                result["original_integrity"] = (
                    "VALID" if len(original) == manifest["originalLength"] and hashlib.sha256(original).hexdigest() == manifest["originalSHA256"] else "INVALID"
                )
            except (InvalidTag, ValueError):
                result["original_integrity"] = "INVALID"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--trusted-public-point-hex", default=None,
                        help="Externally obtained P-256 uncompressed public point (hex)")
    args = parser.parse_args()
    trusted = bytes.fromhex(args.trusted_public_point_hex) if args.trusted_public_point_hex else None
    report = verify_bytes(args.file.read_bytes(), trusted_public_point=trusted)
    print(json.dumps(report, indent=2))
    return 0 if report["structure"] == report["manifest_signature"] == report["ciphertext_integrity"] == "VALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
