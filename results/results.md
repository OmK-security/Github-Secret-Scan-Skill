# Test results

Fake repo: 4 commits, 2 branches, 15 planted secrets in 13 files, 5 decoy files, 3 hard cases. Scored by file.

| Scanner | True-secret files found | Deleted/branch-only found | False-positive files | Hard cases found |
|---|---|---|---|---|
| fallback scanner (skill) | 10/13 | 3/3 | 1 | 0/3 |
| detect-secrets (tree only) | 8/13 | 0/3 | 4 | 2/3 |
| trufflehog3 rules-only (history) | 4/13 | 1/3 | 0 | 0/3 |
| trufflehog3 +entropy (history) | 9/13 | 2/3 | 2 | 1/3 |
| all three layered | 12/13 | 3/3 | 4 | 2/3 |

Remediation test: `git filter-repo --sensitive-data-removal` took the fallback scanner from 19 findings to 10. The 10 left were secrets that were not targeted; none remained in deleted files or the other branch.
