#!/usr/bin/env python3
"""Build one normalized, digest-pinned ARGUS Rules release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--version", required=True)
parser.add_argument("--output", required=True, type=pathlib.Path)
args = parser.parse_args()
if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", args.version):
    raise SystemExit("invalid Rules version")
root = pathlib.Path(__file__).resolve().parents[1]
lock = json.loads((root / "locks/rules.lock.json").read_text())
overrides = json.loads((root / "overrides.json").read_text())["templateIds"]


def sha256(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def safe_files(source: pathlib.Path):
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise SystemExit(f"symlink is forbidden: {relative}")
        if path.is_dir():
            continue
        if not path.is_file() or len(relative.parts) > 20:
            raise SystemExit(f"unsafe Rules path: {relative}")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o111 and path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            raise SystemExit(f"executable Rules file is forbidden: {relative}")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise SystemExit(f"oversized Rules file: {relative}")
        yield path


args.output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="argus-rules-") as temporary:
    work = pathlib.Path(temporary)
    stage = work / "stage"
    (stage / "templates").mkdir(parents=True)
    (stage / "fingerprints").mkdir()
    (stage / "licenses").mkdir()
    seen_ids: dict[str, tuple[str, pathlib.Path, str]] = {}
    content_digests: set[str] = set()
    source_stats = []
    cves: set[str] = set()
    for item in lock["sources"]:
        checkout = work / item["id"]
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", f"https://github.com/{item['repository']}.git"], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "-q", "--depth", "1", "origin", item["commit"]], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
        actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        if actual != item["commit"]:
            raise SystemExit(f"{item['id']}: source commit mismatch")
        license_path = checkout / item["licensePath"]
        if not license_path.is_file():
            raise SystemExit(f"{item['id']}: license is missing")
        license_target = stage / "licenses" / item["id"]
        license_target.mkdir()
        shutil.copyfile(license_path, license_target / "LICENSE")
        count = 0
        if item["kind"] == "coverage-metadata":
            metadata = checkout / "data/all.json"
            source_stats.append({"id": item["id"], "kind": item["kind"], "files": 0, "metadataSha256": sha256(metadata), "metadataBytes": metadata.stat().st_size})
            continue
        for include in item["include"]:
            source = checkout / include
            if not source.exists():
                raise SystemExit(f"{item['id']}: missing selected path {include}")
            candidates = [source] if source.is_file() else safe_files(source)
            for path in candidates:
                relative = pathlib.Path(path.name) if source.is_file() else path.relative_to(source)
                if item["kind"] == "fingerprints":
                    target = stage / "fingerprints" / item["id"] / relative
                else:
                    if path.suffix not in {".yaml", ".yml"}:
                        continue
                    text = path.read_text(errors="strict")
                    if re.search(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", text):
                        raise SystemExit(f"{item['id']}: embedded private key in {relative}")
                    if re.search(r"(?m)^(?:code|javascript|headless):\s*$", text):
                        raise SystemExit(f"{item['id']}: dangerous protocol in {relative}")
                    match = re.search(r"(?m)^id:\s*['\"]?([A-Za-z0-9_.:-]+)", text)
                    if match is None:
                        raise SystemExit(f"{item['id']}: template lacks a valid id: {relative}")
                    template_id = match.group(1)
                    file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    if file_digest in content_digests:
                        continue
                    existing = seen_ids.get(template_id)
                    if existing is not None:
                        selected = overrides.get(template_id)
                        if selected not in {existing[0], item["id"]}:
                            raise SystemExit(f"duplicate template id {template_id}: {existing[0]} and {item['id']}; add an explicit override")
                        if selected == existing[0]:
                            continue
                        existing[1].unlink()
                    target = stage / "templates" / item["id"] / relative
                    seen_ids[template_id] = (item["id"], target, file_digest)
                    content_digests.add(file_digest)
                    cves.update(value.upper() for value in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE))
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                os.chmod(target, 0o444)
                count += 1
        source_stats.append({"id": item["id"], "kind": item["kind"], "files": count})
    files = []
    for path in sorted(stage.rglob("*")):
        if path.is_file():
            files.append({"path": str(path.relative_to(stage)), "size": path.stat().st_size, "sha256": sha256(path)})
    statistics = {"templateCount": len(seen_ids), "cveCount": len(cves), "fingerprintFiles": sum(item["files"] for item in source_stats if item["kind"] == "fingerprints"), "sources": source_stats}
    manifest = {"schemaVersion": 1, "component": "rules", "version": args.version, "rulesSchema": 1, "nucleiVersionRange": ">=3.11.1 <4.0.0", "sources": lock["sources"], "statistics": statistics, "files": files}
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (stage / "rules.lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    (stage / "statistics.json").write_text(json.dumps(statistics, indent=2, sort_keys=True) + "\n")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "data", "name": "argus-rules", "version": args.version}}, "components": [{"type": "data", "name": item["id"], "version": item["commit"], "licenses": [{"license": {"id": item["license"]}}]} for item in lock["sources"]]}
    (stage / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    provenance = {"schemaVersion": 1, "builder": "argus-supply/argus-rules", "buildType": "pinned-curation", "materials": [{"uri": f"https://github.com/{item['repository']}", "digest": {"gitCommit": item["commit"]}} for item in lock["sources"]]}
    (stage / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    epoch = subprocess.check_output(["git", "-C", str(root), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    archive = args.output / f"argus-rules_{args.version}.tar.zst"
    tar_process = subprocess.Popen(["tar", "--sort=name", f"--mtime=@{epoch}", "--owner=0", "--group=0", "--numeric-owner", "-C", str(stage), "-cf", "-", "."], stdout=subprocess.PIPE)
    zstd = subprocess.run(["zstd", "-19", "-T0", "-q", "-o", str(archive)], stdin=tar_process.stdout, check=True)
    del zstd
    if tar_process.stdout is not None:
        tar_process.stdout.close()
    if tar_process.wait() != 0:
        raise SystemExit("tar failed")
    for name in ("manifest.json", "rules.lock.json", "statistics.json", "sbom.cdx.json", "provenance.json"):
        shutil.copyfile(stage / name, args.output / name)
release_files = sorted(path for path in args.output.iterdir() if path.is_file() and path.name != "SHA256SUMS")
(args.output / "SHA256SUMS").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in release_files))
print(f"built Rules {args.version}")
