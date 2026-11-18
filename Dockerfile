# Build the generated TypeScript MCP server.
FROM node:22-bookworm-slim AS server-build
WORKDIR /app/server
COPY server/package.json server/package-lock.json ./
RUN npm ci
COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build && npm prune --omit=dev

# Runtime: Python gateway (FastMCP) + Node for the stdio child.
FROM python:3.11-slim-bookworm
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node
RUN pip install --no-cache-dir "fastmcp==4.1.7" \
    && useradd --system --uid 10001 --home-dir /var/lib/bigcapital-mcp mcp \
    && mkdir -p /var/lib/bigcapital-mcp && chown mcp /var/lib/bigcapital-mcp
WORKDIR /app
COPY --from=server-build /app/server/build ./server/build
COPY --from=server-build /app/server/node_modules ./server/node_modules
COPY --from=server-build /app/server/package.json ./server/package.json
COPY gateway ./gateway
ENV BIGCAPITAL_TOOL_ALLOWLIST_FILE=/app/gateway/allowlist.txt \
    FASTMCP_HOME=/var/lib/bigcapital-mcp \
    PORT=8080
USER mcp
EXPOSE 8080
CMD ["python", "/app/gateway/app.py"]
