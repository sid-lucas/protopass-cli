# ProtoPass CLI

ProtoPass CLI is a **prototype command-line password manager**, inspired by modern password managers such as Proton Pass.  
It provides a local-first CLI interface to manage vaults, credentials, and secrets using a secure architecture.

This project was developed as part of a **Bachelor Thesis** and is intended for **demonstration and experimentation purposes only**.

---

## Features

- Command-line interface (`protopass`)
- User registration and authentication
- Vault and item management
- Password generation
- TOTP support
- Local secure agent for sensitive key handling
- Local API server management
- SimpleLogin integration
- Interactive shell mode

---

## Installation (Linux)

### Option A — Standalone binary (no Python needed)
1) Download `protopass` from the latest release.
2) Make it executable and run:
   ```bash
   chmod +x protopass
   ./protopass --help
   ```

### Option B — Python package (pip)
Requires Python 3.11+.
- Virtualenv (recommended):
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate    # Windows: .venv\Scripts\activate
  pip install ./dist/protopass_cli-0.1.0-py3-none-any.whl
  protopass --help
  ```
- System-wide (if you prefer):
  ```bash
  pip install ./dist/protopass_cli-0.1.0-py3-none-any.whl
  ```

Choose the mode you like: binary for zero Python dependency, pip if you want it in your Python environment.

## Data locations (both options)
- Base directory: `~/.protopass/`
- Agent socket: `~/.protopass/agent.sock`
- Client state: `~/.protopass/client_data/account_state.json`
- Server data (users/sessions/vaults): `~/.protopass/server_data/`
- Server logs: `~/.protopass/server/server.log`

## Basic commands
Start the local API server first:
```bash
protopass server start
```

Then use direct commands:
```bash
protopass register -u alice
protopass login -u alice
protopass vault create
protopass item create -t login -n "Example" -e alice@example.com -pA
protopass item list
```

Or launch the interactive shell:
```bash
protopass shell
```

## Development from source
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
protopass --help
```

## Disclaimer
ProtoPass CLI is a prototype for academic purposes. Security is experimental and it is **not intended for production use**.
