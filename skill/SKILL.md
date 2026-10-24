---
name: github-secret-scan
description: Check whether API keys, passwords, tokens or certificates are committed to a GitHub repo or org, including git history. Use for secret scanning, leaked credential audits, and cleanup after a leak.
---

# GitHub secret scan

Find secrets committed to GitHub repos, rank them, and fix them in the right order. Work on repos the user owns or is authorized to test. Never print a full secret: show the first 4 characters and the length. Never use a found credential for anything except the provider's own validity check, and only when the user owns it.

## Step 1: Scope and authorization
1. Confirm the target (one repo, a user's repos, or an org) and that the user owns it or has written permission.
2. List where secrets can hide, then decide what is in scope: every branch, tags, pull request refs (`refs/pull/*`), forks, archived repos, wikis, issues and PR comments, gists, releases and uploaded assets, CI logs, container images, zip files and other binaries.

## Step 2: Collect a full copy
- `git clone --mirror <url> repo.git` (a mirror holds all branches and tags; a shallow clone hides history, so never use `--depth`).
- Add PR refs when readable: `git -C repo.git fetch origin '+refs/pull/*:refs/pull/*'` (read-only refs can fail; note it and move on).
- For an org, list repos with `gh api --paginate /orgs/<org>/repos` and loop.
- Wikis are separate repos: `<repo>.wiki.git`.

## Step 3: Ask GitHub what it already knows
- Is scanning on? `gh api /repos/<o>/<r>` and read `security_and_analysis` (`secret_scanning`, `secret_scanning_push_protection`).
- Existing alerts: `gh api --paginate /repos/<o>/<r>/secret-scanning/alerts?state=open`. Note the secret type, validity (when shown) and the locations endpoint.
- Know the limits: public repos get scanning free; private repos need GitHub Secret Protection. Passwords have no push protection or validity check. Pattern coverage is provider-based, so custom or internal secrets can be missed.

## Step 4: Detect in layers (run at least two tools and compare, per OWASP)
Run each on the full history, not just the current files.
1. **gitleaks** (patterns + entropy): `gitleaks git --redact -f json -r gitleaks.json repo.git`; also `gitleaks dir --redact .` for the working tree. Add `--max-decode-depth 3` to decode base64/hex and `--max-archive-depth 2` to look inside zip/tar. Exit code 1 means leaks found. Gitleaks is in maintenance mode; the maintainer is moving focus to Betterleaks.
2. **TruffleHog** (patterns + live verification): `trufflehog git file://./repo.git --results=verified,unknown --json`. Statuses are verified, unverified and unknown. Verification contacts the provider, so run it only on credentials the user owns.
3. **detect-secrets** (working tree only, broad heuristics, noisy): `detect-secrets scan --all-files`. It does not read history.
4. **Fallback** if none is installed: use the script in the last section. It scans every commit on every ref and the reflog, checks file names, and decodes base64.
5. **File-name sweep** over all history, catching secrets no regex knows: `.env*`, `id_rsa`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `*.tfstate`, `*.tfvars`, `.npmrc`, `.pypirc`, `.netrc`, `credentials*`, `kubeconfig`, service-account JSON, `wp-config.php`.
   `git -C repo.git log --all --name-only --format= | sort -u | grep -Ei '<patterns>'`
6. **Archives and binaries:** list them with `git -C repo.git log --all --name-only --format= | grep -Ei '\.(zip|tar|gz|jar|war|7z)$'` and scan their contents (gitleaks archive depth, or unpack to a temp folder and rescan).

## Step 5: Triage every finding
For each one record: secret type, file, line, first commit that added it, author and date, branches and tags that contain it, and whether the exact value is still in the checked-out tree or only in history.
1. **Dedupe** the same value across tools and commits.
2. **Classify:** real credential, test fixture or placeholder (`YOUR_KEY_HERE`, `changeme`, example hosts), or non-secret (git SHAs, UUIDs, hashes, integrity strings). Expect false positives from generic and entropy rules.
3. **Check if live,** only for credentials the user owns: TruffleHog verification, GitHub validity status, or the provider's own "whoami" call (for AWS, `aws sts get-caller-identity`). A deleted-from-code key can still be live.
4. **Rank:** live and powerful (cloud admin, payment, production database) > live and narrow > not live. Raise severity if the repo is public or was ever public, if the secret is old (more time exposed), or if forks exist.

## Step 6: Respond (order matters)
1. **Revoke or rotate first.** Once a secret was pushed, treat it as burned, whether or not the repo is private. Issue a new least-privilege secret, preferably short-lived or fetched from a secret manager.
2. **Check for misuse:** review the provider's audit log for use of the old key during the whole exposure window (CloudTrail, GitHub audit log, payment dashboard). Start an incident record if there was unexpected use.
3. **Remove it from the code:** read it from environment variables or a secret manager instead, and add the file to `.gitignore`.
4. **Rewrite history only if needed** (compliance, or a secret that cannot be rotated). It breaks commit hashes and signatures and disrupts open PRs:
   - Work on a fresh clone. Needs git-filter-repo 2.47+.
   - Remove a file: `git filter-repo --sensitive-data-removal --invert-paths --path <file>`
   - Replace values: `git filter-repo --sensitive-data-removal --replace-text replace.txt` (lines like `regex:ghp_[A-Za-z0-9]{36}==>***REMOVED***`)
   - Count affected PR refs in `.git/filter-repo/changed-refs`, then `git push --force --mirror origin`. `refs/pull/*` will be rejected because GitHub keeps them read-only.
   - Contact GitHub Support for cached views and PR refs; give the repo name, number of PRs, and the First Changed Commit(s).
   - Forks keep the old commits: ask owners to delete or clean them. Collaborators must re-clone or rebase, never merge old branches back.
5. **Re-scan** the rewritten history and confirm the finding is gone.

## Step 7: Prevent repeats
- Turn on secret scanning and push protection (repo or org level). Require a reason for bypasses and review them.
- Add a pre-commit hook (gitleaks or detect-secrets) and a CI job that fails on new findings. Keep a baseline so only new findings block.
- Add custom patterns for internal token formats.
- Keep `.env*`, key files and state files in `.gitignore`; commit only `.env.example` with placeholders.
- Prefer short-lived credentials: OIDC from GitHub Actions to the cloud instead of stored keys.
- Allowlist narrowly (a specific commit, path and rule), never a whole folder, and review allowlists regularly.
- Keep a runbook: who to notify, how to rotate, who depends on each secret.

## Step 8: Report
Give a table: severity, type, location (file:line, commit, branch), in-HEAD or history-only, live status, action taken, owner. State which tools ran, what was out of scope, and what these tools cannot see (split strings, encrypted blobs, unusual formats, secrets in images or screenshots). Say that "no findings" means none found by these tools, not none present.

## Fallback scanner (Step 4.4)
Save as `secret_scan_fallback.py` and run `python3 -I secret_scan_fallback.py /path/to/repo [--json out.json]`. It prints redacted findings and exits 1 if any exist. Its rules cover AWS, GitHub, Slack, Google, Stripe, private keys, JWTs, credentialed URLs, keyword assignments with an entropy check, base64-wrapped secrets and suspicious file names. Known gaps: split strings, low-entropy human passwords, archives.

```python
#!/usr/bin/env python3
"""Fallback secret scanner: full git history + working tree. Output is redacted.
usage: python3 secret_scan_fallback.py /path/to/repo [--json out.json]"""
import base64, json, math, re, subprocess, sys

RULES = {
    "aws-access-key-id": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "github-token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
    "slack-token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "google-api-key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "stripe-live-key": r"\b[sr]k_live_[0-9A-Za-z]{16,}\b",
    "private-key-block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "url-with-credentials": r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:[^\s:/@'\"]{3,}@[^\s'\"]+",
}
GENERIC = re.compile(
    r"""(?ix)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)[\w.-]*)
        \s*[:=]\s*['"]?([^\s'"#,;]{8,})""")
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
PLACEHOLDER = re.compile(
    r"(?i)(your[_-]|example|placeholder|changeme|change_me|<.*>|xxxx|\*{3,}|dummy|sample|todo|\$\{|\{\{|%\(|os\.environ|getenv|process\.env|redacted|null|none|true|false)")
SUSPECT_FILES = re.compile(
    r"(?i)(^|/)(\.env(\..*)?|id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|pfx|p12|jks|keystore|ppk)|"
    r"credentials(\.json)?|\.npmrc|\.pypirc|\.netrc|.*\.tfstate|.*\.tfvars|kubeconfig|"
    r"service[-_]?account.*\.json|wp-config\.php|secrets?\.(ya?ml|json|toml))$")
SAFE_FILES = re.compile(r"(?i)\.(env\.example|env\.sample|env\.template)$|\.pub$")


def entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def redact(v):
    return v[:4] + "*" * 6 + f"({len(v)} chars)" if len(v) > 8 else "*" * 6


def check_line(line, where, out):
    for rid, rx in RULES.items():
        for m in re.finditer(rx, line):
            val = m.group(0)
            if PLACEHOLDER.search(val) and rid not in ("private-key-block",):
                continue
            out.append({**where, "rule": rid, "match": redact(val), "_raw": val})
    g = GENERIC.search(line)
    if g and not PLACEHOLDER.search(g.group(2)) and entropy(g.group(2)) >= 3.0:
        out.append({**where, "rule": "generic-credential-assignment", "match": f"{g.group(1)}={redact(g.group(2))}", "_raw": g.group(2)})
    for b in B64.findall(line):
        try:
            dec = base64.b64decode(b + "=" * (-len(b) % 4), validate=False).decode("utf-8")
        except Exception:
            continue
        if dec.isprintable() and len(dec) >= 12 and (GENERIC.search(dec) or any(re.search(r, dec) for r in RULES.values())):
            out.append({**where, "rule": "base64-encoded-secret", "match": redact(b), "_raw": b})


def git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, errors="replace", check=True).stdout


def scan_history(repo):
    out, commit, path, lineno = [], None, None, 0
    log = git(repo, "log", "--all", "--reflog", "-p", "-U0", "--no-color",
              "--format=@@COMMIT %H|%an|%ad|%D", "--date=short")
    for raw in log.splitlines():
        if raw.startswith("@@COMMIT "):
            h, au, dt, refs = (raw[9:].split("|") + ["", "", "", ""])[:4]
            commit = {"commit": h[:10], "author": au, "date": dt, "refs": refs}
        elif raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("@@ ") and "+" in raw:
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+") and not raw.startswith("+++") and path:
            lineno += 1
            check_line(raw[1:], {**commit, "file": path, "line": lineno}, out)
    # file-name heuristics over every path ever committed
    seen = set()
    for raw in git(repo, "log", "--all", "--reflog", "--name-only", "--no-color",
                   "--format=@@COMMIT %H").splitlines():
        if raw.startswith("@@COMMIT "):
            c = raw[9:19]
        elif raw and (c, raw) not in seen and SUSPECT_FILES.search(raw) and not SAFE_FILES.search(raw):
            seen.add((c, raw))
            out.append({"commit": c, "file": raw, "line": 0, "rule": "suspicious-filename", "match": "(file name)", "_raw": ""})
    return out


def still_in_head(repo, f):
    """True if the exact value is still present in the checked-out tree (not just history)."""
    if not f["_raw"]:
        return f["file"] in set(git(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    try:
        return f["_raw"] in git(repo, "show", f"HEAD:{f['file']}")
    except subprocess.CalledProcessError:
        return False


def main():
    repo = sys.argv[1]
    findings = scan_history(repo)
    uniq = {}
    for f in findings:
        k = (f["file"], f["rule"], f["match"])
        f["in_head"] = still_in_head(repo, f)
        uniq.setdefault(k, f)  # keep newest occurrence (log is newest-first)
    res = sorted(uniq.values(), key=lambda f: (not f["in_head"], f["rule"], f["file"]))
    for f in res:
        f.pop("_raw")  # never print or store the raw secret
    for f in res:
        print(f'{f["rule"]:32} {f["file"]}:{f["line"]:<4} {f["commit"]} {"in-HEAD" if f["in_head"] else "not-in-HEAD":12} {f["match"]}')
    print(f"\n{len(res)} unique findings ({sum(not f['in_head'] for f in res)} not in the checked-out tree: history or other branches)", file=sys.stderr)
    if "--json" in sys.argv:
        json.dump(res, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=2)
    sys.exit(1 if res else 0)


if __name__ == "__main__":
    main()
```
