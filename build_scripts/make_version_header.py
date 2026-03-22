from pathlib import Path
import subprocess
import re
import sys


def get_git_short_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return "nogit"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    version_txt = root / "version.txt"
    out_header = root / "VersionGenerated.h"

    version_str = version_txt.read_text(encoding="ascii").strip()

    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version_str):
        print(f"Invalid version format in {version_txt}: {version_str}", file=sys.stderr)
        return 1

    comma_version = version_str.replace(".", ",")
    git_hash = get_git_short_hash()

    content = f"""#pragma once

#define VER_FILEVERSION {comma_version}
#define VER_PRODUCTVERSION {comma_version}

#define VER_FILEVERSION_STR "{version_str}"
#define VER_PRODUCTVERSION_STR "{version_str} ({git_hash})"
"""

    old_content = None
    if out_header.exists():
        old_content = out_header.read_text(encoding="utf-8")

    if content != old_content:
        out_header.write_text(content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
