#!/usr/bin/env python3
"""Validate Rules locks and explicit conflict policy."""

from __future__ import annotations

import json
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
lock = json.loads((root / "locks/rules.lock.json").read_text())
expected = {"nuclei-templates", "fingerprinthub", "missing-cve-metadata", "wordfence-cve"}
sources = lock.get("sources", [])
if lock.get("schemaVersion") != 1 or {item.get("id") for item in sources} != expected:
    raise SystemExit("rules lock must contain the four reviewed sources")
for item in sources:
    if not re.fullmatch(r"[0-9a-f]{40}", item.get("commit", "")):
        raise SystemExit(f"{item.get('id')}: commit must be a full SHA")
    if item.get("license") != "MIT":
        raise SystemExit(f"{item['id']}: unreviewed license")
metadata = next(item for item in sources if item["id"] == "missing-cve-metadata")
if metadata["kind"] != "coverage-metadata" or metadata["include"]:
    raise SystemExit("missing-cve source must remain metadata-only")
overrides = json.loads((root / "overrides.json").read_text())
if overrides.get("schemaVersion") != 1 or not isinstance(overrides.get("templateIds"), dict):
    raise SystemExit("invalid conflict overrides")
print("validated 4 immutable Rules sources")
