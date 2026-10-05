#!/usr/bin/env bash
#
# monarch-mcp-stdio.sh — launch the WRITE-ENABLED Monarch MCP server over stdio.
#
# This is the launcher an MCP client (e.g. KiroCrew / kiro-cli) names in its
# command-form config:
#
#     "monarch-write": {
#       "command": "/Users/rberger/work/agents/monarch-mcp-server/deploy/monarch-mcp-stdio.sh"
#     }
#
# WHY stdio and not HTTP
# ----------------------
# The read-only server runs over streamable-http on 127.0.0.1:8000. Writes
# un-gate session- and data-mutating tools, and the HTTP transport does not
# authenticate callers — anything that reaches the port gets in. Running the
# write-enabled server over STDIO removes the network port entirely: the only
# speaker to the server is the client process that spawned it over the
# stdin/stdout pipe. The pipe IS the auth boundary; there is no port, no proxy,
# and no API key to store or leak.
#
# WHAT it does differently from the running read-only container
# -------------------------------------------------------------
#   - MONARCH_MCP_TRANSPORT=stdio   (image default is streamable-http)
#   - MONARCH_MCP_READ_ONLY=1       (KEPT ON — the gate must be engaged for the
#                                    allowlist to mean anything; see below)
#   - MONARCH_MCP_WRITE_ALLOW=...   (curated subset re-exposed on top of reads)
#   - no  -p / port publish         (nothing listens on any TCP port)
#
# WHY READ_ONLY stays 1 (not 0)
# -----------------------------
# The server's allowlist (read_only.py) re-exposes a curated write subset ONLY
# while read-only mode is engaged. READ_ONLY=1 turns the gate ON (every write
# hidden); MONARCH_MCP_WRITE_ALLOW then re-exposes exactly the named subset.
# Setting READ_ONLY=0 would DISABLE the gate entirely and expose ALL 29 writes
# — the opposite of what we want. "Read-only + a curated allowlist" is the
# whole mechanism, so READ_ONLY=1 is correct here and deliberate.
#   - --rm                          (per-session container; nothing left running)
#   - -i (no -t)                    (interactive stdin, no TTY — required for the
#                                    MCP stdio framing on stdin/stdout)
#
# The named `monarch-session` volume is mounted exactly as the read-only
# container mounts it, so the same validated Monarch login is reused.
#
# SAFETY
# ------
# Even with READ_ONLY=0, the server's NEVER_ALLOWLISTABLE floor keeps the
# destructive and session tools (delete_transaction, monarch_logout, etc.)
# structurally unregistered regardless of what the allowlist below names. The
# allowlist can only ADD from the categorization-safe subset.

set -euo pipefail

# --- Configuration (edit here, not in the client config) --------------------

# Container image built from this repo. Tagged separately from the read-only
# image (monarch-mcp-server:latest) so a write rebuild cannot clobber or
# re-point the read-only tag that the long-running :8000 container uses.
IMAGE="${MONARCH_MCP_IMAGE:-monarch-mcp-server:write}"

# Named Docker volume holding the Monarch session (same one the read-only
# container uses). Mounts at the in-image home the server reads.
SESSION_VOLUME="${MONARCH_MCP_SESSION_VOLUME:-monarch-session}"
SESSION_MOUNT="/home/app/.monarch-mcp-server"

# Curated write allowlist for transaction categorization. Everything NOT named
# here stays gated; everything in NEVER_ALLOWLISTABLE stays gated even if named.
WRITE_ALLOW="${MONARCH_MCP_WRITE_ALLOW:-\
create_transaction_rule,\
update_transaction_rule,\
categorize_transaction,\
bulk_categorize_transactions,\
bulk_update_transactions,\
mark_transaction_reviewed,\
update_transaction_notes}"

# --- Preflight --------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
  echo "monarch-mcp-stdio: docker not found on PATH" >&2
  exit 127
fi

# Fail loudly if the image is missing, rather than letting docker print its own
# error onto the stdio channel the MCP client is parsing.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "monarch-mcp-stdio: image '$IMAGE' not found — build it first (docker build -t $IMAGE .)" >&2
  exit 1
fi

# --- Launch -----------------------------------------------------------------
#
# exec so the container's lifetime is this process's lifetime: when the client
# closes the pipe, docker run exits and --rm reaps the container.

exec docker run \
  --rm \
  -i \
  -e MONARCH_MCP_TRANSPORT=stdio \
  -e MONARCH_MCP_READ_ONLY=1 \
  -e "MONARCH_MCP_WRITE_ALLOW=${WRITE_ALLOW}" \
  -v "${SESSION_VOLUME}:${SESSION_MOUNT}" \
  "$IMAGE"
