#!/usr/bin/env python3
"""spg-policyparametersanitizer: I read a policy file the way an
auditor reads it, looking for the one thing that should never be
there: a real secret typed into a parameter.

Policies drift toward convenience. Someone needs the integration
to work today, so the API key goes in the parameter file next to
the region and the timeout, and there it stays, copied into every
backup and every repo clone. I look for exactly that: values
parked under credential-shaped key names, well-known key formats
(AWS access keys, private key blocks), credential-shaped values in
URLs, and values random enough to be machine-generated secrets
rather than words a person chose.

Every finding is reported by file, by location, and by kind. The
matched value itself is never printed, never logged, never
written anywhere by this tool in readable form. A sanitizer that
leaks the secret into its own report has done the one job it
exists to prevent. With --sanitize I write a cleaned copy with
each secret value replaced by a placeholder, so the file can be
shared with the findings list without sharing the secrets.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# Key names that should hold references to secrets (a vault path,
# an environment variable name), never the secret itself.
SECRET_KEY = re.compile(
    r"(password|passwd|pwd|secret|token|api[-_]?key|apikey|"
    r"access[-_]?key|private[-_]?key|client[-_]?secret|auth)", re.I)

AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
URL_CRED = re.compile(r"://[^/\s:@]+:[^/\s:@]+@")

PLACEHOLDER = re.compile(
    r"^(\$\{[^}]*\}|<[^>]*>|\$\w+|env:.*|vault:.*|kms:.*|"
    r"redacted|changeme|change-me|example|sample|placeholder|"
    r"none|null|true|false|xxx+|\*+|your[-_ ].*)$", re.I)

MIN_SECRET_LEN = 12
ENTROPY_MIN = 4.2


def shannon(text):
    """Shannon entropy in bits per character. Human words sit low;
    generated tokens sit high."""
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classify(key, value):
    """The finding kind for one parameter, or None when it is clean.
    I check formats first, then key names, then shape, so the most
    specific accusation wins."""
    v = str(value).strip()
    if PRIVATE_KEY.search(v):
        return "private key material"
    if AWS_KEY.search(v):
        return "AWS access key id"
    if URL_CRED.search(v):
        return "credentials embedded in a URL"
    if PLACEHOLDER.match(v):
        # A reference, a template, or an obvious dummy value. The
        # whole point of the convention is that these are safe.
        return None
    if SECRET_KEY.search(key or ""):
        if len(v) >= 6:
            return "value under a credential-shaped key"
        return None
    if len(v) >= MIN_SECRET_LEN and not any(c.isspace() for c in v):
        if shannon(v) >= ENTROPY_MIN:
            return "high-entropy value (looks machine-generated)"
    return None


def walk(value, key, path):
    """Yield (location, key, kind, value) for a parsed JSON tree."""
    if isinstance(value, dict):
        for k, sub in value.items():
            yield from walk(sub, str(k), path + [str(k)])
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            yield from walk(sub, key, path + [f"[{i}]"])
    else:
        kind = classify(key, value)
        if kind:
            yield (".".join(path), key, kind, str(value))


def scan_json(text, name):
    """(findings, sanitized_text_or_None, parsed_ok)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], None, False
    findings = list(walk(data, "", []))
    if not findings:
        return [], None, True

    def scrub(value, key):
        if isinstance(value, dict):
            return {k: scrub(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v, key) for v in value]
        if classify(key, value):
            return "[REDACTED]"
        return value

    cleaned = json.dumps(scrub(data, ""), indent=2) + "\n"
    hits = [{"location": loc, "kind": kind} for loc, _k, kind, _v
            in findings]
    return hits, cleaned, True


KV_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]\s*(.+?)\s*$")


def scan_kv(text, name):
    """key=value and key: value files, one parameter per line."""
    findings = []
    out_lines = []
    parsed_any = False
    for lineno, line in enumerate(text.splitlines(), 1):
        m = KV_LINE.match(line)
        stripped = line.strip()
        if not m or stripped.startswith(("#", ";", "//")):
            out_lines.append(line)
            continue
        parsed_any = True
        key, value = m.group(1), m.group(2)
        kind = classify(key, value)
        if kind:
            findings.append({"location": f"line {lineno}",
                             "parameter": key, "kind": kind})
            sep = "=" if "=" in line.split(key, 1)[1][:2] else ":"
            out_lines.append(f"{key}{sep} [REDACTED]")
        else:
            out_lines.append(line)
    if not parsed_any:
        return [], None, False
    cleaned = "\n".join(out_lines) + "\n" if findings else None
    return findings, cleaned, True


def scan_text_patterns(text, name):
    """Format scans that work on any file: key blocks and AWS ids
    hiding in free-form text still count as parsed findings."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if PRIVATE_KEY.search(line):
            findings.append({"location": f"line {lineno}",
                             "kind": "private key material"})
        elif AWS_KEY.search(line):
            findings.append({"location": f"line {lineno}",
                             "kind": "AWS access key id"})
    cleaned = None
    if findings:
        cleaned = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
        cleaned = AWS_KEY.sub("[REDACTED]", cleaned)
    return findings, cleaned, bool(findings)


def scan_file(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        hits, cleaned, ok = scan_json(text, path.name)
        if ok:
            return hits, cleaned, True
    hits, cleaned, ok = scan_kv(text, path.name)
    if ok:
        return hits, cleaned, True
    return scan_text_patterns(text, path.name)


def run(args):
    path = Path(args.file)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    if args.sanitize:
        resolved_out = Path(args.sanitize).resolve()
        if resolved_out == path.resolve():
            print("error: --sanitize target is the policy file "
                  "itself; I will not overwrite a policy in place. "
                  "Choose a different output path.",
                  file=sys.stderr)
            return 2
    findings, cleaned, parsed = scan_file(path)
    if not parsed:
        print(f"error: {path} held nothing I could parse as policy "
              "parameters; nothing was scanned", file=sys.stderr)
        return 2
    if findings and cleaned is not None and args.sanitize:
        Path(args.sanitize).write_text(cleaned, encoding="utf-8")
        print(f"wrote sanitized copy: {args.sanitize}",
              file=sys.stderr)
    if args.json:
        print(json.dumps({"file": str(path), "findings": findings},
                         indent=2))
    else:
        for hit in findings:
            where = hit["location"]
            param = (f" parameter {hit['parameter']}"
                     if hit.get("parameter") else "")
            print(f"{path}: {where}{param}: {hit['kind']} "
                  f"(value redacted)")
        if findings:
            print(f"{len(findings)} finding(s) in {path}; values "
                  "were never printed", file=sys.stderr)
        else:
            print(f"{path}: clean, no hardcoded secrets found")
    return 1 if findings else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="spg-policyparametersanitizer",
        description="Scan a policy file for secrets hardcoded in "
                    "its parameters and report them redacted.")
    parser.add_argument("file", help="policy file to scan (JSON or "
                                     "key=value text)")
    parser.add_argument("--sanitize", metavar="OUT",
                        help="also write a cleaned copy to OUT with "
                             "each secret value replaced by a "
                             "placeholder; OUT must not be the "
                             "input file")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON (locations and "
                             "kinds only, never values)")
    return parser


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
