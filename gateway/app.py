"""HTTP gateway for the Bigcapital MCP server.

Runs the generated stdio server (server/build/index.js) as a child process and
exposes it over streamable HTTP behind Google OAuth. Three independent gates:

1. Google OAuth (FastMCP GoogleProvider): no valid token -> 401.
2. Email allowlist: the token's verified Google email must be in
   BIGCAPITAL_MCP_ALLOWED_EMAILS, checked on every MCP request.
3. Tool allowlist: the child server only loads tools named in
   BIGCAPITAL_TOOL_ALLOWLIST_FILE, and this gateway refuses calls to any
   other name as well.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sys

from fastmcp.client.transports import StdioTransport
from fastmcp.exceptions import AuthorizationError, ToolError
from fastmcp.server import create_proxy
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token
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


def parse_emails(raw: str) -> frozenset[str]:
    emails = frozenset(e.strip().lower() for e in raw.split(",") if e.strip())
    if not emails:
        sys.exit("BIGCAPITAL_MCP_ALLOWED_EMAILS must list at least one email")
    return emails


class AccessGate(Middleware):
    """Rejects callers whose Google email is not allowed, and unlisted tools."""

    def __init__(self, allowed_emails: frozenset[str], allowed_tools: frozenset[str]):
        self.allowed_emails = allowed_emails
        self.allowed_tools = allowed_tools

    def _check_caller(self) -> None:
        token = get_access_token()
        claims = getattr(token, "claims", None) or {}
        email = str(claims.get("email") or "").lower()
        verified = claims.get("email_verified")
        if verified in (False, "false"):
            email = ""
        if not email or email not in self.allowed_emails:
            log.warning("Rejected MCP request from non-allowlisted caller")
            raise AuthorizationError("This Google account is not allowed to use this server.")

    async def on_request(self, context: MiddlewareContext, call_next):
        self._check_caller()
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        name = getattr(context.message, "name", None)
        if name not in self.allowed_tools:
            raise ToolError(f"Tool '{name}' is not enabled on this server.")
        return await call_next(context)


def build():
    logging.basicConfig(level=logging.INFO)
    allowlist_path = _require("BIGCAPITAL_TOOL_ALLOWLIST_FILE")
    allowed_tools = load_allowlist(allowlist_path)
    allowed_emails = parse_emails(_require("BIGCAPITAL_MCP_ALLOWED_EMAILS"))
    _require("API_BASE_URL")
    _require("BIGCAPITAL_BEARER_TOKEN")

    auth = GoogleProvider(
        client_id=_require("BIGCAPITAL_MCP_OAUTH_CLIENT_ID"),
        client_secret=_require("BIGCAPITAL_MCP_OAUTH_CLIENT_SECRET"),
        base_url=_require("BIGCAPITAL_MCP_BASE_URL"),
        jwt_signing_key=_require("BIGCAPITAL_MCP_JWT_SIGNING_KEY"),
        required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
    )

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

    server = create_proxy(transport, name="Bigcapital (Halifax Automation)", auth=auth)
    server.add_middleware(AccessGate(allowed_emails, allowed_tools))
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
