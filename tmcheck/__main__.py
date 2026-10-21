"""python -m tmcheck MODEL.yaml"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .core import (ModelError, coverage_gaps, load_model, policy_findings,
                   rank, validate)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    try:
        model = load_model(argv[0])
    except ModelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    issues = validate(model)
    gaps = coverage_gaps(model)
    policy = policy_findings(model)
    ranked = rank(model)
    report = {
        "issues": [asdict(x) for x in issues],
        "gaps": [asdict(x) for x in gaps],
        "policy": [asdict(x) for x in policy],
        "ranked": [asdict(x) for x in ranked],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if (issues or gaps or policy) else 0


if __name__ == "__main__":
    sys.exit(main())
