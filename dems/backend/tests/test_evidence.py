"""Evidence ingestion: hash matching, MIME magic bytes, path traversal, vault protection, integrity, download."""
import os
import uuid

import pytest
from sqlalchemy import func, select

from app.db.models import AuditLog, Evidence, EvidenceKey, Role
from app.db.session import get_sessionmaker
from app.services import evidence_service as es
from app.services.errors import ServiceError
from tests.helpers import ELF, JPEG, PDF, PE, PNG, TEXT, make_actor, make_case, sha256, upload


@pytest.fixture
async def world(client):
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    admin = await make_actor(client, "admin1", Role.ADMIN)
    auditor = await make_actor(client, "aud1", Role.AUDITOR)
    case = await make_case(client, inv)
    return inv, admin, auditor, case


async def count(model, *where):
    async with get_sessionmaker()() as db:
        return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def audit_codes():
    async with get_sessionmaker()() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.action == "EVIDENCE_REJECTED"))).scalars().all()
        return [r.details_json["code"] for r in rows]


def vault_files(env):
    return [p for p in env.vault_path.rglob("*") if p.is_file()]


# ---------------------------------------------------------------- happy path
async def test_upload_encrypts_hashes_and_records_everything(client, env, world):
    inv, _, _, case = world
    data = JPEG
    r = await upload(client, inv, case["id"], data, description="phone photo", tags="phone, dcim")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sha256_server"] == body["sha256_client"] == sha256(data)
    assert body["detected_mime"] == "image/jpeg" and body["size_bytes"] == len(data)
    assert body["tags"] == ["phone", "dcim"]

    path = env.vault_path / case["id"] / f"{body['id']}.enc"
    assert path.exists()
    blob = path.read_bytes()
    assert blob.startswith(b"DEMS") and data[100:164] not in blob      # encrypted, not plaintext
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in path.parent.iterdir()] == [path.name]      # no temp files left behind

    assert await count(EvidenceKey, EvidenceKey.evidence_id == uuid.UUID(body["id"])) == 1
    chain = (await client.get(f"/custody/{case['id']}", headers=inv.headers)).json()["items"]
    assert [e["action"] for e in chain] == ["INGEST"] and chain[0]["sequence_no"] == 1
    assert (await client.get(f"/custody/{case['id']}/verify", headers=inv.headers)).json()["valid"] is True


async def test_verify_then_download_roundtrip_and_custody_events(client, env, world):
    inv, _, _, case = world
    ev = (await upload(client, inv, case["id"], PDF, "report.pdf", "application/pdf")).json()

    v = await client.post(f"/evidence/{ev['id']}/verify", headers=inv.headers)
    assert v.status_code == 200 and v.json()["status"] == "pass"

    for expected_count in (1, 2):                                       # one DOWNLOADED event per download
        d = await client.get(f"/evidence/{ev['id']}/download", headers=inv.headers)
        assert d.status_code == 200 and d.content == PDF
        assert d.headers["content-disposition"].startswith("attachment;")
        assert 'filename="report.pdf"' in d.headers["content-disposition"]
        assert d.headers["x-content-type-options"] == "nosniff" and d.headers["x-content-sha256"] == sha256(PDF)
        actions = [e["action"] for e in (await client.get(f"/custody/{case['id']}", headers=inv.headers)).json()["items"]]
        assert actions.count("DOWNLOADED") == expected_count
    assert "INTEGRITY_VERIFIED" in actions
    assert (await client.get(f"/custody/{case['id']}/verify", headers=inv.headers)).json()["valid"] is True


# ---------------------------------------------------------------- client / server hash matching
async def test_client_hash_mismatch_rejected_and_nothing_persisted(client, env, world):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], JPEG, client_sha=sha256(b"something else"))
    assert r.status_code == 422 and r.json()["code"] == "hash_mismatch"
    assert await count(Evidence) == 0 and vault_files(env) == []
    assert await audit_codes() == ["hash_mismatch"]                       # refusal is audited


@pytest.mark.parametrize("bad", ["", "abc", "z" * 64, "A" * 63, sha256(b"x") + "0"])
async def test_malformed_client_hash_rejected(client, env, world, bad):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], JPEG, client_sha=bad or "x")
    assert r.status_code == 422 and await count(Evidence) == 0


async def test_uppercase_client_hash_is_accepted_and_normalised(client, env, world):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], JPEG, client_sha=sha256(JPEG).upper())
    assert r.status_code == 201 and r.json()["sha256_client"] == sha256(JPEG)


# ---------------------------------------------------------------- MIME magic bytes
@pytest.mark.parametrize("data,name,ctype,mime", [
    (JPEG, "a.jpg", "image/jpeg", "image/jpeg"),
    (PNG, "a.png", "image/png", "image/png"),
    (PDF, "a.pdf", "application/pdf", "application/pdf"),
    (TEXT, "log.txt", "text/plain", "text/plain"),
    (PE, "sample.exe", "application/x-msdownload", "application/vnd.microsoft.portable-executable"),
    (ELF, "sample.bin", "application/octet-stream", "application/x-executable"),
])
async def test_genuine_files_are_accepted_with_detected_type(client, env, world, data, name, ctype, mime):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], data, name, ctype)
    assert r.status_code == 201, r.text
    assert r.json()["detected_mime"] == mime


@pytest.mark.parametrize("data,name,ctype", [
    (PE, "holiday.jpg", "image/jpeg"),             # executable renamed to .jpg
    (ELF, "scan.pdf", "application/pdf"),          # ELF binary renamed to .pdf
    (TEXT, "invoice.pdf", "application/pdf"),      # plain text pretending to be a PDF
    (JPEG, "notes.txt", "text/plain"),             # image pretending to be text
    (PDF, "a.bin", "image/png"),                   # lying Content-Type
])
async def test_mime_spoofing_rejected(client, env, world, data, name, ctype):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], data, name, ctype)
    assert r.status_code == 415 and r.json()["code"] == "unsupported_media_type"
    assert await count(Evidence) == 0 and vault_files(env) == []
    assert await audit_codes() == ["unsupported_media_type"]


@pytest.mark.env(ALLOWED_MIME_TYPES="image/*,application/pdf")
async def test_allow_list_is_enforced(client, env, world):
    inv, _, _, case = world
    assert (await upload(client, inv, case["id"], TEXT, "log.txt", "text/plain")).status_code == 415
    assert (await upload(client, inv, case["id"], PNG, "ok.png", "image/png")).status_code == 201


async def test_empty_file_rejected(client, env, world):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], b"", "empty.txt", "text/plain")
    assert r.status_code == 400 and r.json()["code"] == "empty_file"


# ---------------------------------------------------------------- size limit
@pytest.mark.env(UPLOAD_MAX_BYTES=20000)
async def test_size_limit_enforced(client, env, world):
    inv, _, _, case = world
    big = os.urandom(30_000)
    r = await upload(client, inv, case["id"], big, "big.bin", "application/octet-stream")
    assert r.status_code == 413 and vault_files(env) == [] and await count(Evidence) == 0


# ---------------------------------------------------------------- path traversal
@pytest.mark.parametrize("name", [
    "../../etc/passwd", "..\\..\\windows\\win.ini", "a/../../b.jpg", "../x.jpg", "ok/../../../root.jpg",
])  # NUL bytes never reach the API layer (the multipart parser drops them); unit-tested below
async def test_path_traversal_filenames_rejected(client, env, world, name):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], JPEG, name)
    assert r.status_code == 400 and r.json()["code"] == "invalid_filename"
    assert await count(Evidence) == 0 and vault_files(env) == []


async def test_directory_parts_stripped_and_vault_path_is_server_generated(client, env, world):
    inv, _, _, case = world
    r = await upload(client, inv, case["id"], JPEG, "/etc/shadow/shadow.jpg")
    # absolute path -> display name "shadow.jpg"; the storage path ignores names entirely
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["original_filename"] == "shadow.jpg"
    files = vault_files(env)
    assert len(files) == 1 and files[0].name == f"{ev['id']}.enc"
    assert files[0].resolve().is_relative_to(env.vault_path.resolve())


@pytest.mark.parametrize("raw,expected", [
    ("report.pdf", "report.pdf"),
    ("/var/tmp/report.pdf", "report.pdf"),
    ("C:\\Users\\bob\\report.pdf", "report.pdf"),
    ("  .hidden. ", "hidden"),
    ("a<b>c:d\"e|f?g*h.txt", "abcdefgh.txt"),
    ("evil\u202egnp.exe", "evilgnp.exe"),           # right-to-left override removed
    ("tab\tnew\nline.txt", "tabnewline.txt"),
    ("", "unnamed"), (None, "unnamed"), ("///", "unnamed"), ("...", "unnamed"),
    ("<script>alert(1)</script>.jpg", "script.jpg"),   # '/' acts as a separator; markup cannot survive
])
def test_sanitize_filename(raw, expected):
    assert es.sanitize_filename(raw) == expected


def test_sanitize_filename_length_limit_keeps_extension():
    out = es.sanitize_filename("é" * 300 + ".pdf")
    assert len(out.encode()) <= 255 and out.endswith(".pdf")


@pytest.mark.parametrize("bad", ["..", "../a", "a/..", "a\\..\\b", "x\x00y"])
def test_sanitize_filename_rejects_traversal(bad):
    with pytest.raises(ServiceError) as exc:
        es.sanitize_filename(bad)
    assert exc.value.status_code == 400


def test_vault_path_builder_and_validator(tmp_path):
    root = tmp_path / "vault"; root.mkdir()
    c, e = uuid.uuid4(), uuid.uuid4()
    assert es.vault_file_path(root, c, e) == root.resolve() / str(c) / f"{e}.enc"
    for bad in ("../../etc/passwd", f"{c}/../{e}.enc", f"/{c}/{e}.enc", f"{c}/{e}.enc/../x", "", f"{c}/{e}.txt",
                f"{str(c).upper()}/{e}.enc", f"{c}\\{e}.enc"):
        with pytest.raises(es.VaultPathError):
            es.resolve_stored_path(root, bad)
    with pytest.raises(es.VaultPathError):
        es.vault_file_path(root, "../..", e)  # type: ignore[arg-type]
    assert es.resolve_stored_path(root, f"{c}/{e}.enc") == es.vault_file_path(root, c, e)


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_symlink_escape_blocked(tmp_path):
    root = tmp_path / "vault"; root.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    c, e = uuid.uuid4(), uuid.uuid4()
    (root / str(c)).symlink_to(outside, target_is_directory=True)
    with pytest.raises(es.VaultPathError):
        es.vault_file_path(root, c, e)


def test_content_disposition_is_header_safe():
    h = es.content_disposition('evil"\r\nX-Injected: 1\u00e9.txt')
    assert "\r" not in h and "\n" not in h and h.startswith("attachment;")
    assert "filename*=UTF-8''" in h


# ---------------------------------------------------------------- vault protection and integrity
async def test_tampered_vault_file_fails_verification_and_blocks_download(client, env, world):
    inv, _, _, case = world
    ev = (await upload(client, inv, case["id"], JPEG)).json()
    path = env.vault_path / case["id"] / f"{ev['id']}.enc"
    raw = bytearray(path.read_bytes()); raw[200] ^= 0x01; path.write_bytes(bytes(raw))

    v = await client.post(f"/evidence/{ev['id']}/verify", headers=inv.headers)
    assert v.status_code == 200 and v.json()["status"] == "fail"
    d = await client.get(f"/evidence/{ev['id']}/download", headers=inv.headers)
    assert d.status_code == 409 and d.json()["code"] == "integrity_failure" and JPEG[:50] not in d.content
    actions = [e["action"] for e in (await client.get(f"/custody/{case['id']}", headers=inv.headers)).json()["items"]]
    assert "INTEGRITY_FAILED" in actions and "DOWNLOADED" not in actions
    meta = (await client.get(f"/evidence/{ev['id']}/metadata", headers=inv.headers)).json()
    assert meta["last_verify_result"] == "fail"


async def test_missing_vault_file_reports_error_status(client, env, world):
    inv, _, _, case = world
    ev = (await upload(client, inv, case["id"], JPEG)).json()
    (env.vault_path / case["id"] / f"{ev['id']}.enc").unlink()
    v = await client.post(f"/evidence/{ev['id']}/verify", headers=inv.headers)
    assert v.json()["status"] == "error"


async def test_swapping_ciphertext_between_evidence_items_is_detected(client, env, world):
    inv, _, _, case = world
    a = (await upload(client, inv, case["id"], JPEG)).json()
    b = (await upload(client, inv, case["id"], PNG, "b.png", "image/png")).json()
    pa, pb = (env.vault_path / case["id"] / f"{x['id']}.enc" for x in (a, b))
    pa.write_bytes(pb.read_bytes())                                    # attacker replaces A's file with B's
    assert (await client.post(f"/evidence/{a['id']}/verify", headers=inv.headers)).json()["status"] == "fail"


async def test_database_failure_rolls_back_and_removes_vault_file(client, env, world, monkeypatch):
    inv, _, _, case = world

    async def boom(*a, **k):
        raise RuntimeError("simulated failure after the file was written")

    monkeypatch.setattr(es, "chain_append", boom)
    r = await upload(client, inv, case["id"], JPEG)
    assert r.status_code == 500 and "simulated" not in r.text         # generic error, no internals
    assert await count(Evidence) == 0 and await count(EvidenceKey) == 0 and vault_files(env) == []


# ---------------------------------------------------------------- authorization
async def test_upload_authorization_matrix(client, env, world):
    inv, admin, auditor, case = world
    other = await make_actor(client, "inv2", Role.INVESTIGATOR)
    assert (await upload(client, auditor, case["id"], JPEG)).status_code == 403
    assert (await upload(client, admin, case["id"], JPEG)).status_code == 403
    assert (await upload(client, other, case["id"], JPEG)).status_code == 404   # not assigned: invisible
    anon = await client.post("/evidence/upload", data={"case_id": case["id"], "client_sha256": sha256(JPEG)},
                             files={"file": ("a.jpg", JPEG, "image/jpeg")})
    assert anon.status_code == 401
    assert (await upload(client, inv, case["id"], JPEG)).status_code == 201


async def test_read_authorization(client, env, world):
    inv, admin, auditor, case = world
    other = await make_actor(client, "inv2", Role.INVESTIGATOR)
    ev = (await upload(client, inv, case["id"], JPEG)).json()
    url = f"/evidence/{ev['id']}"
    assert (await client.get(f"{url}/metadata", headers=auditor.headers)).status_code == 200
    assert (await client.get(f"{url}/metadata", headers=admin.headers)).status_code == 200
    assert (await client.get(f"{url}/metadata", headers=other.headers)).status_code == 404
    assert (await client.get(f"{url}/download", headers=auditor.headers)).status_code == 403   # no content for auditors
    assert (await client.get(f"{url}/download", headers=admin.headers)).status_code == 404    # admin not assigned
    assert (await client.get(f"{url}/download", headers=other.headers)).status_code == 404
    assert (await client.post(f"{url}/verify", headers=auditor.headers)).status_code == 200


async def test_closed_case_rejects_uploads(client, env, world):
    inv, _, _, case = world
    assert (await client.post(f"/cases/{case['id']}/close", headers=inv.headers)).status_code == 200
    r = await upload(client, inv, case["id"], JPEG)
    assert r.status_code == 409 and r.json()["code"] == "case_closed"


# ---------------------------------------------------------------- soft delete
async def test_soft_delete_is_admin_only_audited_and_keeps_the_file(client, env, world):
    inv, admin, auditor, case = world
    ev = (await upload(client, inv, case["id"], JPEG)).json()
    url = f"/evidence/{ev['id']}"
    assert (await client.delete(url, params={"reason": "duplicate upload"}, headers=inv.headers)).status_code == 403
    assert (await client.delete(url, params={"reason": "duplicate upload"}, headers=auditor.headers)).status_code == 403
    assert (await client.delete(url, headers=admin.headers)).status_code == 422                 # reason required
    r = await client.delete(url, params={"reason": "duplicate upload"}, headers=admin.headers)
    assert r.status_code == 200 and r.json()["reason"] == "duplicate upload"

    assert (await client.get(f"{url}/metadata", headers=inv.headers)).status_code == 404
    assert (await client.get(f"{url}/download", headers=inv.headers)).status_code == 404
    assert (await client.delete(url, params={"reason": "again"}, headers=admin.headers)).status_code == 404
    assert (env.vault_path / case["id"] / f"{ev['id']}.enc").exists()                          # retained
    listing = (await client.get(f"/cases/{case['id']}/evidence", headers=inv.headers)).json()
    assert listing["total"] == 0
    chain = (await client.get(f"/custody/{case['id']}", headers=inv.headers)).json()["items"]
    assert chain[-1]["action"] == "EVIDENCE_DELETED" and chain[-1]["details_json"]["soft_delete"] is True
    assert (await client.get(f"/custody/{case['id']}/verify", headers=inv.headers)).json()["valid"] is True
