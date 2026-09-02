# ARGUS managed rules

This repository publishes immutable, license-reviewed nuclei templates and fingerprint data for ARGUS. NVD and the `missing-cve-nuclei-templates` dataset are intelligence inputs: only coverage statistics derived from them enter a release.

`locks/rules.lock.json` pins every source commit. `scripts/build.py` rejects unsafe archive entries, duplicate template IDs, embedded private keys, executable files, and oversized inputs before producing a normalized release archive. ARGUS downloads and activates a release only after Catalog approval and operator confirmation.

## Local verification

```sh
python3 scripts/validate.py
python3 scripts/build.py --version 2026.09.03.1 --output dist
```
