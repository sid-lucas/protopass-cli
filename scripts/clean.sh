#!/usr/bin/env bash
set -euo pipefail

# Reset all local ProtoPass state (client + server fixtures).
# - removes client/client_data/account_state.json
# - clears client/logs/*.log
# - clears server/server_data/vaults/*
# - deletes server/server_data/users.json and sessions.json
# - removes local agent socket (~/.protopass/agent.sock) if present

# ---------- Helpers d'affichage ----------
if command -v tput >/dev/null 2>&1; then
  red=$(tput setaf 1); blue=$(tput setaf 2); yellow=$(tput setaf 3); green=$(tput setaf 4); reset=$(tput sgr0)
else
  red=""; blue=""; yellow=""; green=""; reset=""
fi
err()  { printf "%s[ERROR]%s %s\n" "$red" "$reset" "$*"; }
log()  { printf "%s[%s]%s %s\n" "$blue" "$(date +'%H:%M:%S')" "$reset" "$*"; }
warn() { printf "%s[WARNING]%s %s\n" "$yellow" "$reset" "$*"; }
ok()   { printf "%s[OK]%s %s\n" "$green" "$reset" "$*"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLIENT_STATE="$ROOT_DIR/client/client_data/account_state.json"
CLIENT_LOGS_DIR="$ROOT_DIR/client/logs"
SERVER_DATA="$ROOT_DIR/server/server_data"
VAULT_DIR="$SERVER_DATA/vaults"
USERS_FILE="$SERVER_DATA/users.json"
SESSIONS_FILE="$SERVER_DATA/sessions.json"
AGENT_SOCK="$HOME/.protopass/agent.sock"

log "Resetting ProtoPass local state..."

# Client state
if [[ -f "$CLIENT_STATE" ]]; then
  rm -f "$CLIENT_STATE"
  ok "Deleted client state: $CLIENT_STATE"
else
  warn "Client state not found (already clean)"
fi
# Client logs
if [[ -d "$CLIENT_LOGS_DIR" ]]; then
  mapfile -t log_files < <(find "$CLIENT_LOGS_DIR" -type f -name '*.log')
  if (( ${#log_files[@]} > 0 )); then
    for lf in "${log_files[@]}"; do
      : > "$lf"
      printf "  truncated log: %s\n" "$lf"
    done
  fi
  ok "Cleared client logs directory: $CLIENT_LOGS_DIR (${#log_files[@]} truncated)"
else
  warn "Client logs directory not found: $CLIENT_LOGS_DIR"
fi

# Server vaults
if [[ -d "$VAULT_DIR" ]]; then
  mapfile -t vault_files < <(find "$VAULT_DIR" -type f -name '*.json')
  if (( ${#vault_files[@]} > 0 )); then
    find "$VAULT_DIR" -type f -name '*.json' -delete
    for vf in "${vault_files[@]}"; do
      printf "  deleted vault: %s\n" "$vf"
    done
  fi
  ok "Cleared server vaults directory: $VAULT_DIR (${#vault_files[@]} removed)"
else
  warn "Vault directory not found: $VAULT_DIR"
fi

# Server users
if [[ -f "$USERS_FILE" ]]; then
  rm -f "$USERS_FILE"
  ok "Deleted server users file: $USERS_FILE"
else
  warn "Server users file not found (already clean)"
fi

# Server sessions
if [[ -f "$SESSIONS_FILE" ]]; then
  rm -f "$SESSIONS_FILE"
  ok "Deleted server sessions file: $SESSIONS_FILE"
else
  warn "Server sessions file not found (already clean)"
fi


# Agent socket
if [[ -S "$AGENT_SOCK" || -f "$AGENT_SOCK" ]]; then
  rm -f "$AGENT_SOCK"
  ok "Removed agent socket: $AGENT_SOCK"
fi

log "Reset completed."
