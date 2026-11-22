#!/usr/bin/env python3
"""Rename the Anope tree to Warden (one-off, kept for review and re-runs).

Run from the repository root on a clean tree:  python3 -I tools/rename-from-anope.py

What it does, in order:
  1. Source headers: line 1 becomes "Warden IRC Services <repo>", the Anope
     copyright line is kept and a Warden copyright line is added after it,
     "Anope is free software" becomes "Warden is free software".
  2. Every other Anope/anope/ANOPE (also inside identifiers such as
     AnopeInit, anope_dynamic_static_cast, ANOPE_FORMAT) becomes
     Warden/warden/WARDEN, except the protected strings below.
  3. Paths containing "anope" are renamed with git mv.

Protected (left as they are):
  - copyright lines (anything with "Copyright" or "(C)") and their e-mail
    addresses, so credit to the Anope authors stays intact
  - URLs and hostnames on anope.org / anope.de / github.com/anope
  - "$anope$" password-format tags (Atheme's own format, used by db_atheme)
Excluded files: history and credits (docs/CHANGES*, docs/AUTHORS.txt,
docs/LICENSE.txt, .mailmap), vendor/, .github/ (written by hand), README.md,
this script, and binary files.

The RPC method aliases (anope.* -> warden.*) and the anope.conf/anope.json
fallback are done by hand in separate commits, not here.
"""
import re
import subprocess
import sys

REPO_URL = "https://github.com/TehPeGaSuS/warden"
YEAR = "2026"

EXCLUDE = re.compile(
    r"^(docs/CHANGES|docs/AUTHORS\.txt$|docs/LICENSE\.txt$|\.mailmap$|vendor/|\.github/|README\.md$|tools/rename-from-anope\.py$)"
)

# Spans that must survive untouched; replaced by placeholders first.
PROTECT = re.compile(
    r"(?i)"
    r"(?:https?://)?(?:[\w-]+\.)*anope\.(?:org|de)\b[^\s\"'<>)]*"  # anope.org / anope.de URLs + hosts
    r"|github\.com/anope\b[^\s\"'<>)]*"                             # upstream GitHub links
    r"|[\w.+-]+@anope\.org"                                          # e-mail addresses
    r"|\$anope\$"                                                    # Atheme password-format tag
)

HEADER_1 = re.compile(r"^(\s*(?://|#)\s*)Anope IRC Services <https://www\.anope\.org/>\s*$")
HEADER_COPY = re.compile(r"^(\s*(?://|#)\s*)Copyright \(C\) [0-9]{4}(?:-[0-9]{4})? Anope Contributors\s*$")
COPYRIGHT_LINE = re.compile(r"Copyright|\(C\)")


def case_like(src: str, word: str) -> str:
    if src.isupper():
        return word.upper()
    if src[0].isupper():
        return word[0].upper() + word[1:]
    return word.lower()


def rename_text(line: str) -> str:
    saved = []

    def stash(m):
        saved.append(m.group(0))
        return f"\x00{len(saved) - 1}\x00"

    line = PROTECT.sub(stash, line)
    line = re.sub(r"(?i)anope", lambda m: case_like(m.group(0), "warden"), line)
    return re.sub(r"\x00(\d+)\x00", lambda m: saved[int(m.group(1))], line)


def convert(text: str) -> str:
    out = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        nl = line[len(body):]
        m = HEADER_1.match(body)
        if m:
            out.append(f"{m.group(1)}Warden IRC Services <{REPO_URL}>{nl}")
            continue
        m = HEADER_COPY.match(body)
        if m:
            out.append(line)
            out.append(f"{m.group(1)}Copyright (C) {YEAR} Warden Contributors{nl}")
            continue
        if COPYRIGHT_LINE.search(body):
            out.append(line)  # credit stays as written
            continue
        out.append(rename_text(body) + nl)
    return "".join(out)


def git(*args) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    if git("status", "--porcelain", "--untracked-files=no").strip():
        print("working tree not clean, commit or stash first", file=sys.stderr)
        return 1
    files = git("ls-files", "-z").split("\0")
    changed = 0
    for path in filter(None, files):
        if EXCLUDE.match(path):
            continue
        try:
            with open(path, encoding="utf-8", newline="") as f:
                text = f.read()
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue  # binary, submodule or symlink target
        if "\0" in text:
            continue
        new = convert(text)
        if new != text:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new)
            changed += 1

    moved = 0
    for path in filter(None, git("ls-files", "-z").split("\0")):
        if EXCLUDE.match(path) or "anope" not in path.lower():
            continue
        new = re.sub(r"(?i)anope", lambda m: case_like(m.group(0), "warden"), path)
        git("mv", path, new)
        moved += 1

    print(f"{changed} files edited, {moved} files renamed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
