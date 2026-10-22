#!/usr/bin/env python3
"""Build an allowlisted Python release ZIP; never include runtime data."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from codex_proxy_repair import VERSION

FILES = {
    "codex_proxy_repair.py": "codex_proxy_repair.py",
    "run-python.cmd": "run-python.cmd",
    "Python-一键修复.cmd": "Python-一键修复.cmd",
    "Python-仅诊断.cmd": "Python-仅诊断.cmd",
    "Python-还原.cmd": "Python-还原.cmd",
    "PYTHON_README.md": "README.md",
    "LICENSE": "LICENSE",
}


def build(output: Path, force: bool = False) -> Path:
    if not re.fullmatch(r"\d+\.\d+\.\d+", VERSION):
        raise ValueError("Invalid version")
    contents = {}
    for source, target in FILES.items():
        data = (ROOT / source).read_bytes()
        if source.endswith(".cmd"):
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        elif source.endswith(".py"):
            data = data.replace(b"\r\n", b"\n")
        contents[target] = data
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"Codex-Proxy-Repair-Python-v{VERSION}.zip"
    if archive.exists() and not force:
        raise FileExistsError("Archive exists; use --force to rebuild")
    temporary = output / (archive.name + ".building")
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED) as zf:
            for target, data in contents.items():
                entry = zipfile.ZipInfo(f"Codex-Proxy-Repair-Python-v{VERSION}/{target}", (2026, 10, 22, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                zf.writestr(entry, data)
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{checksum}  {archive.name}\n", encoding="ascii", newline="\n")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    archive = build(args.output.resolve(), args.force)
    print(archive)
    print(archive.with_suffix(".zip.sha256"))


if __name__ == "__main__":
    main()
