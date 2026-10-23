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
