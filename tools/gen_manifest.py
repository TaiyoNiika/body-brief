#!/usr/bin/env python3
"""Write MANIFEST.sha256 for the installable files and paste it into the install skill.

Run at the release commit. The install skill then pins that commit and these hashes.
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [
    "LICENSE",
    "whoop/whoop_common.py",
    "whoop/whoop_auth.py",
    "whoop/whoop_fetch.py",
    "tests/test_whoop.py",
]
SKILL = os.path.join(ROOT, "template", "skills", "body-brief-install", "SKILL.md")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_lines():
    return [f"{sha256(os.path.join(ROOT, p))}  {p}" for p in FILES]


def main():
    lines = manifest_lines()
    with open(os.path.join(ROOT, "MANIFEST.sha256"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    skill = open(SKILL, encoding="utf-8").read()
    block = "<!-- MANIFEST:BEGIN -->\n```\n" + "\n".join(lines) + "\n```\n<!-- MANIFEST:END -->"
    new, n = re.subn(r"<!-- MANIFEST:BEGIN -->.*?<!-- MANIFEST:END -->", lambda m: block, skill, flags=re.S)
    if n != 1:
        print("manifest markers not found in install skill", file=sys.stderr)
        return 1
    with open(SKILL, "w", encoding="utf-8") as f:
        f.write(new)
    print(f"manifest: {len(lines)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
