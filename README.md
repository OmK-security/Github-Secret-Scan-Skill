# GitHub Secret Scan (Claude skill)

A step-by-step process for finding API keys, passwords, tokens and certificates that were committed to a GitHub repo, **including ones that were later deleted**, packaged as a Claude skill and tested on a fake repo.

## The problem
Developers sometimes commit secrets by accident (a `.env` file, a cloud key in a config). Deleting the secret in a later commit does not remove it: Git keeps every past version, so it stays in the history, on other branches and in old clones. A key that still works can mean unexpected cloud bills, stolen data or access to production systems.

## The process (8 steps, in `skill/SKILL.md`)
1. Scope and authorization: only scan what you own or have permission to test
2. Collect a full copy (`git clone --mirror`, never shallow)
3. Ask GitHub what it already knows (secret scanning alerts, push protection status)
4. Detect in layers: gitleaks, TruffleHog, detect-secrets, a file-name sweep, an archive check, plus a built-in fallback scanner
5. Triage: remove duplicates and false positives, check whether the key is live, rank by risk
6. Respond in order: **rotate or revoke first**, check the provider's logs for misuse, remove from code, rewrite history only if needed, re-scan
7. Prevent repeats: push protection, pre-commit hook, CI check, short-lived credentials
8. Report, including what the tools cannot see

## What's in this repo
| Path | What it is |
|---|---|
| `skill/SKILL.md` | The Claude skill (the process above plus the fallback scanner) |
| `scripts/secret_scan_fallback.py` | Fallback scanner: scans every commit on every ref, prints redacted findings |
| `test/build_test_repo.py` | Builds a fake repo with planted fake secrets, decoys and hard cases |
| `test/score.py`, `test/run_test.sh` | Run three scanners on the fake repo and score them |
| `results/` | Output of the test run |

## Results
| Scanner | True-secret files found | Deleted/branch-only found | False-positive files | Hard cases found |
|---|---|---|---|---|
| fallback scanner (skill) | 10/13 | 3/3 | 1 | 0/3 |
| detect-secrets (tree only) | 8/13 | 0/3 | 4 | 2/3 |
| trufflehog3 rules-only (history) | 4/13 | 1/3 | 0 | 0/3 |
| trufflehog3 +entropy (history) | 9/13 | 2/3 | 2 | 1/3 |
| all three layered | 12/13 | 3/3 | 4 | 2/3 |

"True-secret files found" is out of 13. "Deleted/branch-only" is out of 3 (a `.env` and a token that were deleted, and a token that exists only on an unmerged branch). "Hard cases" is out of 3 (a split token, a weak password, a key inside a zip). See `results/results.md` for details.

What this shows: no single scanner was enough. A scanner that reads only current files found none of the deleted secrets, and nothing found the key hidden in a zip file. Layering tools found the most.

## Real-world check
I ran the process on my own public repo, [Alert-Triage-Agent](https://github.com/OmK-security/Alert-Triage-Agent), and the results are attached below.

| Check | Result |
|---|---|
| Full-history scan, all branches (27 commits) | 0 findings |
| Sweep for `.env`, key, state and credential file names | None ever committed |
| Archive files (zip, tar) | None |
| detect-secrets on current files | 1 finding, a false alarm: the name of a Workload Identity Federation provider, which is an identifier and not a credential |

The repo uses keyless authentication from GitHub Actions to Google Cloud, so there was no stored cloud key to leak.

This covers only the repo's commits. Pull request refs, issues, wikis and forks were not scanned, and "no findings" means none found by these tools, not none present.

## Limits:
- It is a small, synthetic test I designed myself. It is **not a benchmark** and says nothing about how these tools rank in real projects.
- I wrote the fallback scanner and the test repo, so the fallback's score is not independent evidence.
- gitleaks and TruffleHog (Truffle Security) could not be installed in my test environment, so they were **not** tested. Their commands in the skill come from their documentation. `trufflehog3` in the table is a different, Python-based tool.
- All secrets are randomly generated fakes. The private key is a throwaway created at build time. The fake repo is generated when you run the test and is not stored here.

## Run the test yourself
```bash
pip install detect-secrets trufflehog3
./test/run_test.sh        # needs git, openssl, python3
```

## Use the skill
Add `skill/SKILL.md` as a skill in Claude, then ask: "Check my repo for leaked secrets." Only point it at repos you own or have permission to test.

## Sources
GitHub Docs (secret scanning, push protection, removing sensitive data), OWASP Secrets Management Cheat Sheet, and the gitleaks, TruffleHog and detect-secrets documentation.

## License
MIT
