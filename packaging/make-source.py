#!/usr/bin/env python3
import gzip
import hashlib
import os
from pathlib import Path
import sys
import tarfile

VERSION = sys.argv[1] if len(sys.argv) > 1 else "0.2.0"
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else ROOT / "dist"
PREFIX = f"dkim-lite-{VERSION}"
INCLUDE = [
    ".cargo", "Cargo.toml", "Cargo.lock", "LICENSE", "README.md",
    "OPERATIONS.md", "SECURITY.md", "dkim-lite.conf.example", "packaging",
    "src", "tests", "testing", "vendor",
]
EXCLUDE = {
    # The report contains archive/RPM digests and therefore cannot be embedded
    # in the archive whose digest it records.
    "testing/VALIDATION.md",
    "testing/rocky10-fips.xml",
    "testing/rocky10-fips.ks",
    "testing/rocky9-fips.xml",
    "testing/rocky9-fips.ks",
}
EPOCH = 1785456000


def members():
    paths = []
    for name in INCLUDE:
        path = ROOT / name
        if path.is_dir():
            paths.append(path)
            paths.extend(path.rglob("*"))
        else:
            paths.append(path)
    return sorted(
        (path for path in paths if path.relative_to(ROOT).as_posix() not in EXCLUDE),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


OUTPUT.mkdir(parents=True, exist_ok=True)
archive = OUTPUT / f"{PREFIX}.tar.gz"
with archive.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=EPOCH) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in members():
                relative = path.relative_to(ROOT).as_posix()
                info = tar.gettarinfo(str(path), f"{PREFIX}/{relative}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = EPOCH
                if info.isfile():
                    with path.open("rb") as source:
                        tar.addfile(info, source)
                else:
                    tar.addfile(info)

digest = hashlib.sha256(archive.read_bytes()).hexdigest()
checksum = archive.with_suffix(archive.suffix + ".sha256")
checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
print(archive)
