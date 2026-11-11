#!/usr/bin/env python3
"""Add the "no longer maintained" notice to the top of README.md and the docs home page (run once, at hand-off).

    python3 scripts/handoff/mark_unmaintained.py --version v1.0.0 [--date 2027-01-31]

Running it again replaces the notice instead of adding a second one.
"""
from __future__ import annotations

import argparse
import datetime
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
START, END = "<!-- unmaintained-notice -->", "<!-- /unmaintained-notice -->"


def notice(version: str, date: str) -> str:
    return f"""{START}
> **This project is finished and no longer maintained.** The last release is **{version}** ({date}). Nobody is
> watching issues, pull requests or security reports, and there will be no further updates from this repository.
> It still works and stays available under the Apache 2.0 licence: run it as it is, or **fork it** and carry it on
> (see [FORKING.md](FORKING.md)). If you run it, you are responsible for keeping your own copy safe and up to date.
{END}
"""


def apply(path: Path, text: str) -> None:
    body = path.read_text()
    body = re.sub(re.escape(START) + r".*?" + re.escape(END) + r"\n*", "", body, flags=re.S)
    lines = body.split("\n", 1)
    if lines[0].startswith("# "):  # keep the title first
        body = lines[0] + "\n\n" + text + "\n" + (lines[1].lstrip("\n") if len(lines) > 1 else "")
    else:
        body = text + "\n" + body
    path.write_text(body)
    print(f"notice added to {path.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", required=True, help="the final release tag, e.g. v1.0.0")
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    args = parser.parse_args()
    text = notice(args.version, args.date)
    apply(ROOT / "README.md", text)
    docs_home = ROOT / "docs" / "index.md"
    if docs_home.exists():
        apply(docs_home, text.replace("(FORKING.md)", "(https://github.com/Palmertech-Webdev/fenrir-security/blob/main/FORKING.md)"))


if __name__ == "__main__":
    main()
