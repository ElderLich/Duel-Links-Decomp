"""Rebuild all enrolled units and regenerate public facts, or check a public checkout."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Run tests and public consistency checks without original binaries")
    parser.add_argument("--targets", type=Path, help="Private target path overrides; pinned identities must remain unchanged")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commands = [
        ["-m", "unittest", "discover", "-s", "Tools/Matching", "-p", "test_*.py", "-v"],
        ["-m", "unittest", "discover", "-s", "Tools", "-p", "test_export*.py", "-v"],
    ]
    if not args.check:
        integration = ["Tools/Matching/integrate.py"]
        if args.targets:
            integration += ["--targets", str(args.targets.resolve())]
        commands += [["Tools/export_progress.py", "--prepare-references"], integration, ["Tools/export_progress.py"], ["Tools/export_dashboard.py"], ["Tools/build_site.py"]]
    commands += [["Tools/export_progress.py", "--check"], ["Tools/export_dashboard.py", "--check"], ["Tools/build_site.py", "--check"], ["-m", "unittest", "discover", "-s", "Tools", "-p", "test_build_site.py", "-v"]]
    for command in commands:
        print("\n> python " + " ".join(command), flush=True)
        result = subprocess.run([sys.executable, *command], cwd=root, check=False)
        if result.returncode:
            print("Stopped: this check failed. No later refresh step ran.", file=sys.stderr)
            return result.returncode
    print("Public consistency checks passed." if args.check else "Full integration and public exports passed. Review the diff before publishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
