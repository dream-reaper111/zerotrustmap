from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import PolicyError, analyze_file, boundaries


def main() -> None:
    parser = argparse.ArgumentParser(prog="zerotrustmap")
    parser.add_argument("policy", type=Path, help="authorized AWS IAM identity policy JSON")
    parser.add_argument("--principal", required=True, help="IAM user or role ARN the policy belongs to")
    parser.add_argument("--boundaries", type=Path, help="operator-labelled trust zones JSON")
    parser.add_argument("--previous", type=Path, help="previous report JSON")
    args = parser.parse_args()
    try:
        if args.previous and (args.previous.is_symlink() or not args.previous.is_file()
                              or args.previous.stat().st_size > 16 * 1024 * 1024):
            raise PolicyError("previous report must be a regular JSON file under 16 MiB")
        previous = json.loads(args.previous.read_bytes()) if args.previous else None
        result = analyze_file(args.policy, args.principal, boundaries(args.boundaries), previous)
    except (PolicyError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
