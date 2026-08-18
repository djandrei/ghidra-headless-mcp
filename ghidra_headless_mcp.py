#!/usr/bin/env python3
"""Entry point for ghidra-headless-mcp.

The implementation lives in the ghmcp package; this stays a launcher so the
documented command line (`python ghidra_headless_mcp.py`, and the mcpo wrapper
around it) keeps working as the tool surface grows.

Transport is stdio, so ALL logging goes to stderr; anything on stdout corrupts
the JSON-RPC stream.
"""

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)

from ghmcp import config  # noqa: E402  (configure logging before import chatter)
from ghmcp.tools import mcp  # noqa: E402


def main() -> None:
    logging.getLogger("ghidra_headless_mcp").info(
        "ghidra-headless-mcp starting: project=%s location=%s",
        config.PROJECT_NAME,
        config.PROJECT_LOCATION,
    )
    mcp.run()


if __name__ == "__main__":
    main()
