#!/usr/bin/env python3
"""Convenience runner: `python analyze.py [capture] [options]`.

This just delegates to the package CLI so you can run the tool without the
`-m` module syntax. Examples:

    python analyze.py --demo
    python analyze.py captures/session.pcapng
    python analyze.py export.csv --db output/analysis.db --json output/findings.json
"""
from netsec_analyzer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
