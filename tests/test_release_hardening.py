"""Release-preparation regression checks; not substitutes for iOS device tests."""
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verifier'))
from verify_sealshot import verify_bytes
from test_verifier import fixture, raw


def test_duplicate_envelope_json_field_rejected():
    env, _ = fixture()
    text = raw(env).decode()
    # Same key appears twice; JSON consumers disagree on which value wins.
    text = text.replace('"format":', '"format":"forged", "format":', 1)
    assert verify_bytes(text.encode())['structure'] == 'INVALID'


def test_duplicate_manifest_field_rejected():
    env, _ = fixture()
    manifest = base64.b64decode(env['manifestBase64']).decode()
    manifest = manifest.replace('"ownerID":', '"ownerID":"attacker", "ownerID":', 1)
    env['manifestBase64'] = base64.b64encode(manifest.encode()).decode()
    assert verify_bytes(raw(env))['structure'] == 'INVALID'


def test_invalid_original_length_rejected():
    env, _ = fixture()
    manifest = json.loads(base64.b64decode(env['manifestBase64']))
    manifest['originalLength'] = 100 * 1024 * 1024 + 1
    env['manifestBase64'] = base64.b64encode(json.dumps(manifest).encode()).decode()
    assert verify_bytes(raw(env))['structure'] == 'INVALID'


def test_oversized_owner_rejected():
    env, _ = fixture()
    manifest = json.loads(base64.b64decode(env['manifestBase64']))
    manifest['ownerID'] = 'a' * 257
    env['manifestBase64'] = base64.b64encode(json.dumps(manifest).encode()).decode()
    assert verify_bytes(raw(env))['structure'] == 'INVALID'


def test_trusted_point_match_is_not_full_authorization():
    env, _ = fixture()
    point = base64.b64decode(env['publicKeyX963Base64'])
    report = verify_bytes(raw(env), trusted_public_point=point)
    assert report['signer_authorization'] == 'KEY_MATCH_ONLY'
    assert report['device_attestation'] == 'NOT_VERIFIED'


def test_trusted_point_mismatch_rejected():
    env, _ = fixture()
    report = verify_bytes(raw(env), trusted_public_point=b'\x00' * 65)
    assert report['signer_authorization'] == 'INVALID'


def test_swift_local_view_requires_own_secure_enclave_key():
    source = (ROOT / 'SealShotApp/Crypto/EvidenceSealer.swift').read_text()
    assert 'publicPoint == (try signer.publicPoint(key: localSigningKey))' in source


def test_camera_start_does_not_run_on_main_actor_thread():
    source = (ROOT / 'SealShotApp/Camera/LiveCamera.swift').read_text()
    assert 'sessionQueue.async' in source
    assert 'session.startRunning()' in source


def test_no_external_service_or_shield_dependency():
    swift = '\n'.join(p.read_text() for p in (ROOT / 'SealShotApp').rglob('*.swift'))
    config = (ROOT / 'project.yml').read_text()
    for forbidden in ('import Shield', 'tradedeck', 'tradeneck', 'supabase', 'render.com', 'netlify', 'http://', 'https://'):
        assert forbidden.lower() not in (swift + config).lower()
    assert 'com.sealshot.standalone' in config
