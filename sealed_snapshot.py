#!/usr/bin/env python3
"""
sealed_snapshot.py — one-command SEALED backup/snapshot front door.

Examples:
    python sealed_snapshot.py ~/Pictures --label "Pictures snapshot"
    python sealed_snapshot.py ~/Documents --label "Documents snapshot"
    python sealed_snapshot.py /backups/laptop.img --label "Laptop disk image"

For directories, SEALED creates an encrypted tar.gz bundle. For a live computer,
use OS full-disk encryption and use this helper for selected data or an already-
created backup/disk image file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sealed_core import SealedCore


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal one file or directory into SealedVault")
    parser.add_argument("path", help="file, image, backup, disk-image file, or directory to seal")
    parser.add_argument("--label", help="optional human label")
    parser.add_argument("--storage-dir", default="sealed_storage")
    args = parser.parse_args()

    source = Path(args.path).expanduser().resolve()
    if not source.exists():
        parser.error(f"path does not exist: {source}")

    with SealedCore(storage_dir=args.storage_dir) as core:
        result = core.seal_path(source, label=args.label)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("\nSnapshot sealed. Original files were not deleted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
