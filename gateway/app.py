"""HTTP gateway for the Bigcapital MCP server.

Runs the generated stdio server (server/build/index.js) as a child process and
exposes it over streamable HTTP. Two independent gates:

1. Bearer token: every request needs `Authorization: Bearer <token>`. The
   server only stores SHA-256 hashes of the accepted tokens, one per client,
   in BIGCAPITAL_MCP_TOKEN_SHA256S as `name:hexdigest,name:hexdigest`.
   Missing or unknown tokens get 401.
2. Tool allowlist: the child server only loads tools named in
   BIGCAPITAL_TOOL_ALLOWLIST_FILE, and this gateway refuses calls to any
   other name as well.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import pathlib
import re
import sys

from fastmcp.client.transports import StdioTransport
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.middleware import Middleware, MiddlewareContext

log = logging.getLogger("bigcapital-mcp-gateway")

CHILD_ENV_KEYS = (
    "API_BASE_URL",
    "BIGCAPITAL_BEARER_TOKEN",
    "BIGCAPITAL_ORGANIZATION_ID",
    "BIGCAPITAL_TOOL_ALLOWLIST_FILE",
)


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"{name} must be set")
    return value


def load_allowlist(path: str) -> frozenset[str]:
    names = set()
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(line)
    if not names:
        sys.exit("Tool allowlist is empty")
    return frozenset(names)


def parse_token_hashes(raw: str) -> dict[str, str]:
    """Parses `name:sha256hex,...` into {name: digest}."""
    hashes: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, digest = entry.partition(":")
        digest = digest.strip().lower()
        if not sep or not name.strip() or not re.fullmatch(r"[0-9a-f]{64}", digest):
            sys.exit("BIGCAPITAL_MCP_TOKEN_SHA256S entries must look like name:<64 hex chars>")
        hashes[name.strip()] = digest
    if not hashes:
        sys.exit("BIGCAPITAL_MCP_TOKEN_SHA256S must contain at least one token hash")
    return hashes


class HashedBearerVerifier(TokenVerifier):
    """Accepts a bearer token whose SHA-256 matches one of the configured hashes."""

    def __init__(self, hashes: dict[str, str]):
        super().__init__()
        self._hashes = hashes

    async def verify_token(self, token: str) -> AccessToken | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        matched = None
        for name, expected in self._hashes.items():
            if hmac.compare_digest(digest, expected):
                matched = name
        if matched is None:
            log.warning("Rejected MCP request with an unknown bearer token")
            return None
        return AccessToken(token=token, client_id=matched, scopes=[], expires_at=None)


class ToolGate(Middleware):
    """Refuses calls to tools that are not on the allowlist."""

    def __init__(self, allowed_tools: frozenset[str]):
        self.allowed_tools = allowed_tools

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        name = getattr(context.message, "name", None)
        if name not in self.allowed_tools:
            raise ToolError(f"Tool '{name}' is not enabled on this server.")
        return await call_next(context)


def build():
    logging.basicConfig(level=logging.INFO)
    allowed_tools = load_allowlist(_require("BIGCAPITAL_TOOL_ALLOWLIST_FILE"))
    auth = HashedBearerVerifier(parse_token_hashes(_require("BIGCAPITAL_MCP_TOKEN_SHA256S")))
    _require("API_BASE_URL")
    _require("BIGCAPITAL_BEARER_TOKEN")

    child_env = {k: os.environ[k] for k in CHILD_ENV_KEYS if os.environ.get(k)}
    child_env["PATH"] = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    child_env["NODE_ENV"] = "production"
    transport = StdioTransport(
        command="node",
        args=["/app/server/build/index.js"],
        env=child_env,
        cwd="/app/server",
        keep_alive=True,
    )

    # The generated child server uses an older MCP SDK that only speaks the
    # legacy (handshake) protocol era, so pin the backend to it rather than
    # mirroring a modern front-end client.
    server = create_proxy(
        transport, mode="legacy", name="Bigcapital (Halifax Automation)", auth=auth
    )
    server.add_middleware(ToolGate(allowed_tools))
    return server


def main() -> None:
    server = build()
    server.run(
        transport="http",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        path="/mcp",
    )


if __name__ == "__main__":
    main()
