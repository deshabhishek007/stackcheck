#!/usr/bin/env python3
"""Run StackCheck from a checkout without installing it:  python3 stackcheck.py [scan example.com]

The code lives in the stackcheck/ package next to this file; this wrapper keeps the original
`python3 stackcheck.py` command (and existing systemd/launchd units) working."""
import sys

from stackcheck import main

if __name__ == "__main__":
    sys.exit(main())
