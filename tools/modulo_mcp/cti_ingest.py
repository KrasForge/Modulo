#!/usr/bin/env python3
"""Post a CTI ingest batch to Modulo from a cron watch.

    cti_ingest.py findings.json          # or: some-watch | cti_ingest.py -

The batch format is the one /api/cti/ingest accepts (see docs/features/threat-intelligence.md).
Authentication uses the same MODULO_BASE_URL / MODULO_API_TOKEN(_FILE) variables as the MCP
server, including refresh-token rotation. Prints the ingest summary as JSON; exits 1 on failure.
"""
from __future__ import annotations

import json
import sys

try:
    from .client import ModuloClient, ModuloError
except ImportError:  # Direct invocation.
    from client import ModuloClient, ModuloError


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if argv[1] == "-" else open(argv[1], encoding="utf-8").read()
        batch = json.loads(text)
        result = ModuloClient().cti_ingest(batch)
    except (OSError, ValueError, ModuloError) as error:
        print(f"cti_ingest: {error}", file=sys.stderr)
        return 1
    summary = {key: result.get(key) for key in ("created", "updated", "unchanged", "relationshipsCreated", "watch")}
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
