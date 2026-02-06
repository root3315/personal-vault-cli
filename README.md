# Personal Vault CLI

A secure command-line tool for managing encrypted secrets and credentials. All data is stored in a single encrypted file using AES-256-GCM with a password-derived key via PBKDF2-HMAC-SHA256.

## Features

- End-to-end encryption with AES-256-GCM
- Key derivation via PBKDF2 with 100,000 iterations
- Store, retrieve, delete, and list secrets
- Export secrets as JSON or environment-variable format
- Import secrets from JSON or `.env`-style files
- Password rotation without data loss

## Installation

```bash
pip install -r requirements.txt
```

Make the script executable:

```bash
chmod +x vault.py
```

Optionally alias it for convenience:

```bash
alias vault="python3 /path/to/vault.py"
```

Or symlink to a directory in your `PATH`:

```bash
ln -s /path/to/vault.py ~/.local/bin/vault
```

## Usage

### Initialize a new vault

```bash
python3 vault.py init
```

This creates an encrypted vault file at `~/.personal_vault.json` (configurable via the `VAULT_FILE` environment variable).

### Store a secret

```bash
python3 vault.py set MY_API_KEY
# You will be prompted for the value securely

# Or provide the value directly:
python3 vault.py set MY_API_KEY "sk-abc123"
```

### Retrieve a secret

```bash
python3 vault.py get MY_API_KEY

# Print only the value (useful for scripts):
python3 vault.py get MY_API_KEY -q
```

### Delete a secret

```bash
python3 vault.py delete MY_API_KEY
# Aliases: del, rm
```

### List all secrets

```bash
python3 vault.py list
# Alias: ls
```

### Export secrets

```bash
# As environment variables (default):
python3 vault.py export

# As JSON:
python3 vault.py export -f json

# As encrypted blob for backup:
python3 vault.py export -f json-export
```

### Import secrets

```bash
# From a JSON file:
python3 vault.py import secrets.json

# From a .env-style file:
python3 vault.py import .env
```

### Change vault password

```bash
python3 vault.py change-password
# Alias: passwd
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VAULT_FILE` | `~/.personal_vault.json` | Path to the encrypted vault file |

## Security Notes

- The vault password is never stored on disk or in history (uses `getpass`)
- Each encryption uses a random salt and nonce
- PBKDF2 uses 100,000 iterations to resist brute-force attacks
- Losing the vault password means losing all data — there is no recovery
- The vault file is encrypted at all times on disk

## Command Reference

```
vault init [--force]          Initialize a new vault
vault set <key> [value]       Store a secret
vault get <key> [-q]          Retrieve a secret
vault delete <key>            Delete a secret
vault list                    List all secrets
vault export [-f json|env]    Export secrets
vault import <file>           Import secrets
vault change-password         Change vault password
```

## License

MIT
