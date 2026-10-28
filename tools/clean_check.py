#!/usr/bin/env python3
"""Pre-release check: every count printed here must be 0.

Scans every file in the repository (including untracked ones, excluding .git internals) plus git
commit metadata. Terms are stored hex-encoded so this file does not match itself. Matching text is
never printed, only counts and file:line locations.

Optional: if WHOOP_REDIRECT_URI is set, its host (and parent domain) is compared in memory; the host
itself is never printed.
"""
import hashlib
import math
import os
import re
import subprocess
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Private terms (label -> hex of utf-8 term) live OUTSIDE the repo and are never committed.
# Path: $CLEAN_CHECK_TERMS or ~/.config/body-brief/clean_terms.json. Missing or empty -> FAIL.
TERMS_PATH = os.environ.get("CLEAN_CHECK_TERMS",
                            os.path.expanduser("~/.config/body-brief/clean_terms.json"))


def load_terms():
    try:
        import json
        with open(TERMS_PATH, encoding="utf-8") as fh:
            terms = json.load(fh)
        return terms if isinstance(terms, dict) and terms else None
    except (OSError, ValueError):
        return None


TOKEN_RULES = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "known-prefix": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}"
                               r"|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"),
    "secret-assignment": re.compile(r"(?i)(?:secret|token|password|passwd|api_?key)[A-Za-z0-9_]*\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"),
}
GENERIC = re.compile(r"[A-Za-z0-9_\-+/=.~]{24,}")
PLACEHOLDER = re.compile(r"(?i)fake|example|placeholder|\{\{|<[a-z_-]+>|x{6,}")


def entropy(s):
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def repo_files():
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in (".git", "__pycache__")]
        for f in files:
            yield os.path.join(d, f)


def file_hashes(paths):
    out = set()
    for p in paths:
        with open(p, "rb") as f:
            out.add(hashlib.sha256(f.read()).hexdigest())
    return out


def domain_terms():
    uri = os.environ.get("WHOOP_REDIRECT_URI", "").strip()
    host = (urllib.parse.urlsplit(uri).hostname or "").lower()
    if not host:
        return None
    terms = {host}
    parts = host.split(".")
    if len(parts) > 2:
        terms.add(".".join(parts[-2:]) if len(parts[-2]) > 3 else ".".join(parts[-3:]))
    return terms


def main():
    paths = sorted(repo_files())
    hashes = file_hashes(paths)  # manifest hashes that equal a real file hash are allowed
    texts = {}
    for p in paths:
        try:
            texts[os.path.relpath(p, ROOT)] = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            texts[os.path.relpath(p, ROOT)] = open(p, encoding="latin-1").read()
    try:
        meta = subprocess.run(["git", "-C", ROOT, "log", "--all", "--format=%an%n%ae%n%cn%n%ce%n%B"],
                              capture_output=True, text=True, check=False).stdout
        texts["<git metadata>"] = meta
    except FileNotFoundError:
        pass

    def scan_terms(terms):
        hits = []
        for name, text in texts.items():
            low = text.lower()
            for i, line in enumerate(low.splitlines(), 1):
                if any(t in line for t in terms):
                    hits.append(f"{name}:{i}")
        return hits

    total = 0
    print(f"files scanned: {len(paths)} (+ git metadata)")
    TERMS = load_terms()
    if TERMS is None:
        print("private-terms: NOT LOADED (no private terms file) -> FAIL")
        total += 1
        TERMS = {}
    for label, hx in TERMS.items():
        hits = scan_terms([bytes.fromhex(hx).decode("utf-8").lower()])
        total += len(hits)
        print(f"{label}: {len(hits)}" + (f"  at {', '.join(hits[:10])}" if hits else ""))

    dt = domain_terms()
    if dt is None:
        if os.environ.get("CLEAN_CHECK_ALLOW_NO_DOMAIN") == "1":
            print("redirect-domain: skipped (WHOOP_REDIRECT_URI not set, allowed by CLEAN_CHECK_ALLOW_NO_DOMAIN=1)")
        else:
            print("redirect-domain: NOT CHECKED (set WHOOP_REDIRECT_URI to the maintainer's own redirect) -> FAIL")
            total += 1
    else:
        hits = scan_terms(dt)
        total += len(hits)
        print(f"redirect-domain: {len(hits)}" + (f"  at {', '.join(hits[:10])}" if hits else ""))

    allowed_hash = allowed_placeholder = 0
    for rule, rx in TOKEN_RULES.items():
        hits = []
        for name, text in texts.items():
            for i, line in enumerate(text.splitlines(), 1):
                for m in rx.finditer(line):
                    val = m.group(m.lastindex or 0)
                    if rule == "secret-assignment" and re.match(r"https?://", val):
                        continue  # endpoint URLs such as the public OAuth token endpoint
                    if rule == "secret-assignment" and PLACEHOLDER.search(val):
                        allowed_placeholder += 1
                        continue
                    hits.append(f"{name}:{i}")
        total += len(hits)
        print(f"token-like/{rule}: {len(hits)}" + (f"  at {', '.join(hits[:10])}" if hits else ""))

    hits = []
    for name, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            for m in GENERIC.finditer(line):
                s = m.group(0)
                is_hex = re.fullmatch(r"[0-9a-fA-F]{32,}", s) is not None
                mixed = (len(re.findall(r"[A-Z]", s)) >= 2 and len(re.findall(r"[a-z]", s)) >= 2
                         and len(re.findall(r"\d", s)) >= 2)
                if not (is_hex or mixed) or entropy(s) < 3.5:
                    continue
                if re.fullmatch(r"[0-9a-f]{64}", s) and s in hashes:
                    allowed_hash += 1
                    continue
                if re.fullmatch(r"[0-9a-f]{40}", s) and subprocess.run(
                        ["git", "-C", ROOT, "cat-file", "-e", s + "^{commit}"],
                        capture_output=True).returncode == 0:
                    allowed_hash += 1  # pinned commit SHA that exists in this repo
                    continue
                if PLACEHOLDER.search(s):
                    allowed_placeholder += 1
                    continue
                hits.append(f"{name}:{i}")
    total += len(hits)
    print(f"token-like/high-entropy: {len(hits)}" + (f"  at {', '.join(hits[:10])}" if hits else ""))
    print(f"allowed (not counted): {allowed_hash} manifest sha256 equal to a real file hash, "
          f"{allowed_placeholder} obvious placeholders (FAKE-/example)")
    print("RESULT:", "PASS (all 0)" if total == 0 else f"FAIL ({total} hits)")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
