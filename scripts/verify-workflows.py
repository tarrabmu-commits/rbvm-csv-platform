#!/usr/bin/env python3
from pathlib import Path
import re
import sys


PINNED_ACTION = re.compile(
    r"^\s*(?:-\s+)?uses:\s*([^\s@]+)@([0-9a-f]{40})(?:\s+#\s+v\S+)?\s*$"
)
ANY_ACTION = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#.*)?\s*$")


def main():
    root = Path(__file__).resolve().parent.parent
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    if not workflows:
        raise AssertionError("repository contains no GitHub Actions workflows")

    actions = 0
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        if "permissions:" not in text:
            raise AssertionError(f"workflow lacks explicit permissions: {workflow.name}")
        for line_number, line in enumerate(text.splitlines(), 1):
            if not ANY_ACTION.match(line):
                continue
            actions += 1
            match = PINNED_ACTION.match(line)
            if not match:
                raise AssertionError(
                    f"action is not pinned to a full commit SHA at {workflow.name}:{line_number}"
                )
            repository = match.group(1)
            if not (repository.startswith("actions/") or repository.startswith("github/")):
                raise AssertionError(
                    f"workflow uses an unapproved action owner at {workflow.name}:{line_number}"
                )

    if actions < 12:
        raise AssertionError("workflow action inventory is unexpectedly small")
    print(f"GitHub workflow security checks: PASS ({actions} pinned action uses)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
