#!/usr/bin/env bash
set -euo pipefail

# Simple data set for tests.
# Creates three demo users (alice, bob, charlie) with vaults and items.

CLI="python -m client.cli"

log() { printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"; }

require_login() {
  local user="$1" pass="$2"
  printf '%s\n' "$pass" | $CLI login -u "$user" --password-stdin 1>&2 || true
  python - <<'PY'
from client.core.account_state import AccountState
username = AccountState.username()
ok = AccountState.valid()
print(("OK " + (username or "")) if ok else ("KO " + (username or "")))
PY
}

register_user() {
  local user="$1" pass="$2"
  REG_USER="$user" REG_PASS="$pass" python - <<'PY'
import os, getpass
from types import SimpleNamespace
from client.core import auth

user = os.environ["REG_USER"]
pwd = os.environ["REG_PASS"]
getpass.getpass = lambda prompt="": pwd  # bypass interactive prompt
try:
    auth.register_account(SimpleNamespace(username=user))
except Exception as exc:
    print(f"[warn] register for {user} may have failed (possibly already exists): {exc}")
PY
}

logout_user() {
  $CLI logout >/dev/null 2>&1 || true
}

select_vault_by_name() {
  local name="$1"
  local idx
  idx="$($CLI vault list | awk -v n="$name" '/^[*]?[0-9]+/ {gsub("\\*","",$1); if ($2==n) {print $1; exit}}')"
  if [[ -z "$idx" ]]; then
    echo "Vault '$name' not found for selection" >&2
    return 1
  fi
  $CLI vault select "$idx"
}

ensure_user() {
  local user="$1" pass="$2"
  log "Registering $user"
  register_user "$user" "$pass"
  log "Logging in as $user"
  read -r status logged_user <<<"$(require_login "$user" "$pass")"
  if [[ "$status" != "OK" || "$logged_user" != "$user" ]]; then
    echo "[error] unable to login as $user with provided password. Cleanup client_data and retry." >&2
    exit 1
  fi
}

create_demo_for_alice() {
  local user="alice" pass="alice"
  logout_user
  ensure_user "$user" "$pass"

  log "[$user] Creating vault 'Banking' + items"
  $CLI vault create -n "Banking" -d "Comptes personnels et cartes"
  select_vault_by_name "Banking"
  $CLI item create -t login -n "BCV" -e "alice@example.com" -p "AliceBCV123$" -U "https://www.bcv.ch" --notes "Banque Cantonale Vaudoise - e-banking"
  $CLI item create -t card -n "VisaPremier" --cardnumber "4111111111111111" --expiry "12/26" --holder "Alice Example" --cvv "123" --notes "Carte liée au compte BCV"

  log "[$user] Creating vault 'Work' + items"
  $CLI vault create -n "Work" -d "Accès pro"
  select_vault_by_name "Work"
  $CLI item create -t login -n "Slack" -e "alice@acme.test" -pA -U "https://slack.com/signin"
  $CLI item create -t login -n "GitHub" -e "alice@acme.test" -pA -U "https://github.com" --totp-auto

  logout_user
}

create_demo_for_bob() {
  local user="bob" pass="bob"
  logout_user
  ensure_user "$user" "$pass"

  log "[$user] Creating vault 'Personal' + items"
  $CLI vault create -n "Personal" -d "Logins perso"
  select_vault_by_name "Personal"
  $CLI item create -t login -n "Gmail" -e "bob@example.com" -p "BobGmail123$" -U "https://mail.google.com" --notes "Compte principal" --totp-auto
  $CLI item create -t login -n "Netflix" -e "bob@example.com" -pA -U "https://www.netflix.com/login"

  log "[$user] Creating vault 'Home' + items"
  $CLI vault create -n "Home" -d "Maison"
  select_vault_by_name "Home"
  $CLI item create -t note -n "WiFi" --notes "SSID: WiFi-Swisscom, Password: Can'tHackMe"
  $CLI item create -t identity -n "Identité" --fullname "Bob" --lastname "Dylan" --email "bobdylan@gmail.com" --phone "+41791234567" --notes "Né le 01/01/2000 - Adresse: Rue de Neuchâtel 1, 2000 Neuchâtel"

  logout_user
}

create_demo_for_charlie() {
  local user="charlie" pass="charlie"
  logout_user
  ensure_user "$user" "$pass"

  log "[$user] Creating vault 'Projects' + items"
  $CLI vault create -n "Projects" -d "Accès projets"
  select_vault_by_name "Projects"
  $CLI item create -t login -n "AWS" -e "charlie@cloud.test" -pA -U "https://console.aws.amazon.com" --totp-auto
  $CLI item create -t login -n "HackTheBox" -e "charlie@cloud.test" -p "CasseLaBoite!" -U "https://hackthebox.com" --notes "Juste pour le fun, HTB4Life"

  log "[$user] Creating vault 'Banking' + items"
  $CLI vault create -n "Banking" -d "Comptes bancaires"
  select_vault_by_name "Banking"
  $CLI item create -t login -n "CreditSuisse" -e "charlie@example.com" -pA -U "https://www.credit-suisse.com" --notes "Rest in peace, Credit Suisse..."

  logout_user
}

log "Seeding demo data..."
create_demo_for_alice
create_demo_for_bob
create_demo_for_charlie

log "Dummy data set up completed."
