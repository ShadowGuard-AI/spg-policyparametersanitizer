![Banner](banner.png)

# spg-policyparametersanitizer

I read a policy file the way an auditor reads it, looking for the
one thing that should never be there: a real secret typed straight
into a parameter.

Policies drift toward convenience. Someone needs the integration
working today, so the API key goes into the parameter file next to
the region and the timeout, and there it stays, copied into every
backup and every clone. I hunt for exactly that and report it
without repeating it.

## What I flag

- **A value under a credential-shaped key.** Keys named like
  `password`, `api_key`, `client_secret`, or `token` should hold a
  reference (a vault path, an environment variable), never the
  secret itself.
- **Well-known key formats.** AWS access key ids and embedded
  private key blocks, wherever they appear in the file.
- **Credentials embedded in a URL.** The
  `https://user:password@host` shape inside an endpoint parameter.
- **High-entropy values.** Long values random enough to be
  machine-generated secrets rather than words a person chose.

References and dummies are safe by design and are not flagged:
`${ENV_VAR}`, `<placeholder>`, `vault:...`, `kms:...`,
`changeme`, `example`, and friends. That convention is the correct
way to write these files, and I refuse to train anyone out of it
by crying wolf over it.

## The rule I never break

A finding is reported by file, by location, and by kind. The
matched value itself is never printed, never logged, and never
written anywhere by this tool in readable form. A sanitizer that
leaks the secret into its own report has failed at the one job it
exists to do.

## Install

```bash
git clone https://github.com/ShadowGuard-AI/spg-policyparametersanitizer.git
cd spg-policyparametersanitizer
```

Python 3, standard library only. There is nothing to install.

## Usage

```bash
python3 main.py policy.json
```

```text
policy.json: db_password: value under a credential-shaped key (value redacted)
policy.json: backup_key_id: AWS access key id (value redacted)
policy.json: endpoint: credentials embedded in a URL (value redacted)
```

(Those locations and kinds are from this tool's own test fixture,
whose values are fakes; no real secret has ever appeared in this
README either.)

Write a cleaned copy, secrets replaced, original untouched:

```bash
python3 main.py policy.json --sanitize policy.sanitized.json
```

Machine-readable findings, still redacted:

```bash
python3 main.py policy.properties --json
```

## Parameters

- `file`: the policy file to scan. JSON is parsed as a tree;
  other text is read as `key=value` or `key: value` lines; free
  text is still checked for key material and AWS key ids.
- `--sanitize OUT`: also write a cleaned copy to OUT with each
  secret value replaced by `[REDACTED]`. OUT must not be the
  input file; I will not rewrite a policy in place.
- `--json`: emit findings as JSON, locations and kinds only.

## Exit codes

- `0`: parameters scanned, no hardcoded secrets found.
- `1`: secrets found. The findings are the report; the values are
  not in it.
- `2`: nothing was scanned (missing file, unparseable input) or
  the sanitize target was the input itself. A file I could not
  read never gets reported as clean.

## License

MIT License. See LICENSE.
Copyright (c) Gavin K (@Epsilon0xCell).
