#!/usr/bin/env python3
"""Build a synthetic repo with planted FAKE secrets + decoys. Writes ground_truth.json."""
import base64, json, os, random, shutil, string, subprocess, sys

root = os.path.abspath(sys.argv[1])
rnd = random.Random(20261023)
A = string.ascii_letters + string.digits


def r(n, alpha=A):
    return "".join(rnd.choice(alpha) for _ in range(n))


shutil.rmtree(root, ignore_errors=True)
os.makedirs(root)
env = {**os.environ, "GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": "dev@example.test",
       "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": "dev@example.test"}


def sh(*a, **k):
    return subprocess.run(a, cwd=root, env=env, check=True, capture_output=True, text=True, **k)


def w(path, text):
    p = os.path.join(root, path)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    open(p, "w").write(text)


def commit(msg):
    sh("git", "add", "-A")
    sh("git", "commit", "-q", "-m", msg)


sh("git", "init", "-q", "-b", "main")
S = {}  # planted secrets
S["aws_id"] = "AKIA" + r(16, string.ascii_uppercase + string.digits)
S["aws_secret"] = r(40, A + "+/")
S["gh_pat"] = "ghp_" + r(36)
S["db_pw"] = "Tr0ub4dor&" + r(6)
S["stripe"] = "sk_live_" + r(24)
S["slack"] = "xoxb-" + r(12, string.digits) + "-" + r(12, string.digits) + "-" + r(24)
S["google"] = "AIza" + r(35, A + "_-")
S["yaml_pw"] = "s3cr3t-" + r(6) + "!Pa55"
S["b64_inner"] = "api_key=" + r(32)
S["jwt"] = ".".join(base64.urlsafe_b64encode(x).decode().rstrip("=") for x in
                    [b'{"alg":"HS256","typ":"JWT"}', b'{"sub":"1234567890","name":"svc-account","iat":1516239022}', rnd.randbytes(32)])

# --- commit 1: baseline app, decoys, and live-at-HEAD secrets
w("README.md", "# demo\nSet `API_KEY=YOUR_API_KEY_HERE` before running.\n")
w(".env.example", "DB_PASSWORD=changeme\nAPI_TOKEN=<your-token>\nSTRIPE_KEY=sk_test_xxxxxxxxxxxx\n")
w("tests/test_auth.py", 'import os\npassword = "password"\ntoken = os.environ["TOKEN"]\n')
w("deploy/refs.json", '{"secret_name": "projects/demo/secrets/db-pass/versions/latest", "request_token_id": "123e4567-e89b-12d3-a456-426614174000"}\n')
w("package-lock.json", '{"packages": {"x": {"integrity": "sha512-' + base64.b64encode(rnd.randbytes(64)).decode() + '"}}}\n')
w("app/settings.py", f'DATABASE_URL = "postgresql://admin:{S["db_pw"]}@db.internal:5432/app"\nDEBUG = False\n')
w("app/aws.py", f'AWS_ACCESS_KEY_ID = "{S["aws_id"]}"\naws_secret_access_key = "{S["aws_secret"]}"\n')
w("frontend/map.js", f'const MAPS_KEY = "{S["google"]}";\n')
w("docker-compose.yml", f'services:\n  db:\n    environment:\n      POSTGRES_USER: app\n      password: "{S["yaml_pw"]}"\n')
w("app/utils.py", 'AUTH = "' + base64.b64encode(S["b64_inner"].encode()).decode() + '"\n')
w("docs/api.md", f"Example response header: `Authorization: Bearer {S['jwt']}`\n")
sh("openssl", "genrsa", "-out", os.path.join(root, "keys_server.pem"), "2048")
os.makedirs(os.path.join(root, "keys"), exist_ok=True)
os.rename(os.path.join(root, "keys_server.pem"), os.path.join(root, "keys", "server.pem"))
commit("initial app")

w("app/legacy.py", 'db_password = "Summer2024"\n')
w("app/split.py", 'TOKEN = "ghp_" + "' + r(36) + '"\n')
import zipfile
os.makedirs(os.path.join(root, "backup"), exist_ok=True)
with zipfile.ZipFile(os.path.join(root, "backup", "archive.zip"), "w") as z:
    z.writestr("old.cfg", "stripe_secret=" + "sk_live_" + r(24) + "\n")
w("ci/pins.py", 'commit_token = "9fceb02d0ae598e95dc970b74767f19372d61af8"\n')
# --- commit 2: history-only secrets (added, then removed)
w("deploy.sh", f'#!/bin/sh\nexport GITHUB_TOKEN={S["gh_pat"]}\n./run.sh\n')
w(".env", f'DB_PASSWORD={S["db_pw"]}\nSTRIPE_SECRET={S["stripe"]}\n')
commit("add deploy + env")
w("deploy.sh", "#!/bin/sh\n./run.sh   # token now read from CI secret store\n")
sh("git", "rm", "-q", ".env")
commit("fix: remove token and .env")

# --- branch-only secret (never merged)
sh("git", "checkout", "-q", "-b", "feature/payments")
w("payments/notify.py", f'SLACK_WEBHOOK_TOKEN = "{S["slack"]}"\n')
commit("wip payments notify")
sh("git", "checkout", "-q", "main")

truth = [
    {"id": "aws-id", "file": "app/aws.py", "where": "HEAD"},
    {"id": "aws-secret", "file": "app/aws.py", "where": "HEAD"},
    {"id": "db-url", "file": "app/settings.py", "where": "HEAD"},
    {"id": "google-key", "file": "frontend/map.js", "where": "HEAD"},
    {"id": "yaml-password", "file": "docker-compose.yml", "where": "HEAD"},
    {"id": "base64-secret", "file": "app/utils.py", "where": "HEAD"},
    {"id": "jwt", "file": "docs/api.md", "where": "HEAD"},
    {"id": "private-key", "file": "keys/server.pem", "where": "HEAD"},
    {"id": "low-entropy-password", "file": "app/legacy.py", "where": "HEAD", "hard": True},
    {"id": "split-token", "file": "app/split.py", "where": "HEAD", "hard": True},
    {"id": "secret-in-zip", "file": "backup/archive.zip", "where": "HEAD", "hard": True},
    {"id": "github-pat", "file": "deploy.sh", "where": "history-only"},
    {"id": "dotenv-db", "file": ".env", "where": "history-only"},
    {"id": "dotenv-stripe", "file": ".env", "where": "history-only"},
    {"id": "slack-branch", "file": "payments/notify.py", "where": "branch-only"},
]
json.dump({"truth": truth, "decoy_files": ["README.md", ".env.example", "tests/test_auth.py",
                                           "deploy/refs.json", "package-lock.json", "ci/pins.py"]},
          open(os.path.join(os.path.dirname(root.rstrip("/")), "ground_truth.json"), "w"), indent=2)
print("built", root, "with", len(truth), "planted secrets")
