#!/usr/bin/env bash
set -euo pipefail

# Script interactif de setup d'un employé pour ProtoPass.
# - Demande l'entreprise + le prénom/nom
# - Crée un compte <firstname>_<lastname>
# - Crée deux vaults : "Personnel" (Outlook + Identité pro) et "Business" (outils pro)
# - Génère des mots de passe forts automatiquement

CLI="python -m client.cli"

# ---------- Helpers d'affichage ----------
# Couleurs et fonctions de log (heure + symboles).
if command -v tput >/dev/null 2>&1; then
  bold=$(tput bold); red=$(tput setaf 1); green=$(tput setaf 2)
  yellow=$(tput setaf 3); blue=$(tput setaf 4); reset=$(tput sgr0)
else
  bold=""; red=""; green=""; yellow=""; blue=""; reset=""
fi
log()   { printf "\n%s[%s]%s %s\n" "$blue" "$(date +'%H:%M:%S')" "$reset" "$*"; }
info()  { printf "%s➜%s %s\n" "$yellow" "$reset" "$*"; }
ok()    { printf "%s✓%s %s\n" "$green" "$reset" "$*"; }
err()   { printf "%s✗%s %s\n" "$red" "$reset" "$*"; }

# ---------- Utilitaires ----------
# Enregistre un utilisateur en court-circuitant la saisie interactive du mot de passe.
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
    print(f"[warn] register for {user} may have failed (maybe already exists): {exc}")
PY
}

# Tente un login et retourne "OK <username>" ou "KO <username>" pour vérification.
require_login() {
  local user="$1" pass="$2"
  printf '%s\n' "$pass" | $CLI login -u "$user" --password-stdin 1>&2 || true
  python - <<'PY'
from client.core.account_state import AccountState
user = AccountState.username()
ok = AccountState.valid()
print(("OK " + (user or "")) if ok else ("KO " + (user or "")))
PY
}

logout_user() { $CLI logout >/dev/null 2>&1 || true; }

# Sélectionne un vault par son nom (utile après création).
select_vault_by_name() {
  local name="$1"
  local idx
  idx="$($CLI vault list | awk -v n="$name" '/^[*]?[0-9]+/ {gsub("\\*","",$1); if ($2==n) {print $1; exit}}')"
  if [[ -z "$idx" ]]; then
    err "Vault '$name' not found for selection"
    return 1
  fi
  $CLI vault select "$idx" >/dev/null
}

ask() {
  local prompt="$1" default="${2:-}"
  local input
  if [[ -n "$default" ]]; then
    read -r -p "$(printf "%s%s%s [%s]: " "$bold" "$prompt" "$reset" "$default")" input || true
    input="${input:-$default}"
  else
    read -r -p "$(printf "%s%s%s: " "$bold" "$prompt" "$reset")" input || true
  fi
  echo "$input"
}

sanitize_name() {
  # lowercases and replaces non-alnum with hyphen; keeps short for usernames
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g'
}

# Génère un identifiant interne type "f-fl-1234" (1ère lettre, 2e lettre + 1ère du nom, 4 chiffres).
gen_business_id() {
  local f="$1" l="$2"
  local f1="${f:0:1}"; [[ -z "$f1" ]] && f1="x"
  local f2="${f:1:1}"; [[ -z "$f2" ]] && f2="x"
  local l1="${l:0:1}"; [[ -z "$l1" ]] && l1="x"
  local d1=$(printf '%04d' $((RANDOM % 10000)))
  local d2=$(printf '%02d' $((RANDOM % 100)))
  echo "${f1}${f2}${l1}-${d1}-${d2}" | tr '[:lower:]' '[:upper:]'
}



# ---------- Script flow ----------
# 1) Collecte des entrées utilisateur (sans valeur par défaut affichée).
log "Employee setup wizard"
company_raw=$(ask "Company name")
first_raw=$(ask "First name")
last_raw=$(ask "Last name")

# 2) Normalisation + construction username/email/mot de passe.
company_slug=$(sanitize_name "$company_raw")
first=$(sanitize_name "$first_raw")
last=$(sanitize_name "$last_raw")

username="${first}_${last}"
username="${username:0:20}"  # respect auth username length constraints
email="${first}.${last}@${company_slug}.ch"
bid="$(gen_business_id "$first" "$last")"
account_pass="${username}${bid:9:11}"

info "Company: $company_slug"
info "Employee: $first_raw $last_raw"
info "Username: $username"
info "Email: $email"
info "Business ID: $bid"

# 3) Enregistrement + login (vérification).
log "Registering user"
logout_user
register_user "$username" "$account_pass"

log "Logging in to verify session"
read -r status logged_user <<<"$(require_login "$username" "$account_pass")"
if [[ "$status" != "OK" || "$logged_user" != "$username" ]]; then
  err "Unable to login as $username. If the account already exists with another password, clean client_data and retry."
  exit 1
fi
ok "Logged in as $username"

log "[${username}] Creating vault 'Personnel'"
$CLI vault create -n "Personnel" -d "Accès personnels" >/dev/null
select_vault_by_name "Personnel"

# 4) Ajout identité + Outlook dans le vault Personnel.
$CLI item create -t identity -n "Identité pro" \
  --firstname "$first_raw" --lastname "$last_raw" \
  --email "$email" --phone "+41 79 000 00 00" \
  --notes "Matricule interne: $bid" >/dev/null
ok "Added Identity (business ID: '$bid')"
$CLI item create -t login -n "Outlook" \
  -e "$email" -p "$account_pass" \
  --firstname "$first_raw" --lastname "$last_raw" \
  -U "https://outlook.office.com" \
  --notes "Compte messagerie professionnel" >/dev/null
ok "Added Outlook"

log "[${username}] Creating vault 'Business'"
$CLI vault create -n "Business" -d "Outils de travail" >/dev/null
select_vault_by_name "Business"

# 5) Ajout des outils pro dans le vault Business (mêmes identifiants/email).
create_tool() {
  local name="$1" url="$2"
  $CLI item create -t login -n "$name" \
    -e "$email" -pA \
    --firstname "$first_raw" --lastname "$last_raw" \
    -U "$url" \
    --notes "Accès $name pour ${first_raw} ${last_raw}" >/dev/null
  ok "Added $name"
}

create_tool "GitHub" "https://github.com/login"
create_tool "Slack" "https://slack.com/signin"
create_tool "OVH" "https://www.ovh.com/auth/"
create_tool "Odoo" "https://www.odoo.com/web/login"
create_tool "Nextcloud" "https://nextcloud.${company_slug}.ch"
create_tool "VPN" "https://vpn.${company_slug}.ch"

# 6) Logout et résumé.
logout_user
log "$(printf "Done.\nUser '%s' successfully created with vaults Personnel & Business.\nTemporary password: '%s'. Please ask employee to change their password on first login." "$username" "$account_pass")"
