#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
CORE_COMMIT = "70d23796f2df4a397fdf227596076abc59ac1732"


def seed_reachability_api_example() -> None:
    path = ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    if "### Network Reachability evidence" in text:
        return
    marker = "\n## نتيجة CSV المرجعية\n"
    block = '''
### Network Reachability evidence

استيراد evidence تقنية scoped:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  -H 'Content-Type: text/csv' \\
  --data-binary @network-reachability.csv \\
  http://127.0.0.1:8080/api/v1/network-reachability-imports
```

قراءة current scoped evidence مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  'http://127.0.0.1:8080/api/v1/network-reachability-evidence?asset=web-&originScope=INTERNET&reachabilityStatus=REACHABLE&limit=100'
```

القراءة لا تشتق `internetExposed` على مستوى asset ولا تختار source winner ولا تحسب Risk/Priority/SLA.

'''
    if text.count(marker) != 1:
        raise RuntimeError(f"README reference-results anchor mismatch: {text.count(marker)}")
    path.write_text(text.replace(marker, "\n" + block + marker.lstrip("\n"), 1), encoding="utf-8")


def install_publish_permission_hook() -> None:
    hook = ROOT / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "git restore --source=HEAD --staged --worktree -- "
        ".github/workflows/align-v018-evidence-catchup.yml "
        ".github/workflows/verify.yml .github/workflows/release.yml\n",
        encoding="utf-8",
    )
    os.chmod(hook, 0o755)


def main() -> None:
    seed_reachability_api_example()
    install_publish_permission_hook()
    core = ROOT / "scripts" / "_align-v018-business-impact-core.py"
    with core.open("wb") as output:
        subprocess.run(
            ["git", "show", f"{CORE_COMMIT}:scripts/align-v018-business-impact.py"],
            cwd=ROOT,
            check=True,
            stdout=output,
        )
    try:
        subprocess.run([sys.executable, str(core)], cwd=ROOT, check=True)
    finally:
        core.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
