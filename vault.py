#!/usr/bin/env python3
"""
personal-vault-cli: Manage encrypted secrets and credentials from the terminal.

A secure command-line vault that encrypts secrets using AES-256-GCM
with a password-derived key via PBKDF2.
"""

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aes import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


VAULT_FILE = Path(os.environ.get("VAULT_FILE", os.path.expanduser("~/.personal_vault.json")))
SALT_LENGTH = 16
NONCE_LENGTH = 12
ITERATIONS = 100_000
KEY_LENGTH = 32


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_data(plaintext: str, password: str) -> str:
    """Encrypt plaintext string and return base64-encoded ciphertext package."""
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    package = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(package)


def decrypt_data(encrypted_package: str, password: str) -> str:
    """Decrypt a base64-encoded ciphertext package and return plaintext string."""
    package = json.loads(encrypted_package)
    salt = base64.b64decode(package["salt"])
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["data"])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def load_vault(password: str) -> dict:
    """Load and decrypt the vault file from disk."""
    if not VAULT_FILE.exists():
        return {}
    encrypted = VAULT_FILE.read_text().strip()
    try:
        decrypted = decrypt_data(encrypted, password)
        return json.loads(decrypted)
    except Exception:
        print("Error: Failed to decrypt vault. Wrong password?", file=sys.stderr)
        sys.exit(1)


def save_vault(vault: dict, password: str) -> None:
    """Encrypt and save the vault file to disk."""
    plaintext = json.dumps(vault, indent=2)
    encrypted = encrypt_data(plaintext, password)
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    VAULT_FILE.write_text(encrypted)


def get_password(prompt: str = "Vault password", confirm: bool = False) -> str:
    """Prompt user for vault password securely."""
    password = getpass.getpass(f"{prompt}: ")
    if confirm:
        confirm_pw = getpass.getpass(f"Confirm {prompt}: ")
        if password != confirm_pw:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return password


def cmd_init(args):
    """Initialize a new encrypted vault file."""
    if VAULT_FILE.exists() and not getattr(args, "force", False):
        print(f"Error: Vault already exists at {VAULT_FILE}. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    password = get_password("Set vault password", confirm=True)
    save_vault({}, password)
    print(f"Vault initialized at {VAULT_FILE}")


def cmd_set(args):
    """Store a secret in the vault."""
    password = get_password()
    vault = load_vault(password)
    key = args.key
    value = args.value if args.value else getpass.getpass(f"Value for '{key}': ")
    vault[key] = value
    save_vault(vault, password)
    print(f"Secret '{key}' stored successfully.")


def cmd_get(args):
    """Retrieve and display a secret from the vault."""
    password = get_password()
    vault = load_vault(password)
    key = args.key
    if key not in vault:
        print(f"Error: Secret '{key}' not found in vault.", file=sys.stderr)
        sys.exit(1)
    if getattr(args, "quiet", False):
        print(vault[key])
    else:
        print(f"{key} = {vault[key]}")


def cmd_delete(args):
    """Remove a secret from the vault."""
    password = get_password()
    vault = load_vault(password)
    key = args.key
    if key not in vault:
        print(f"Error: Secret '{key}' not found in vault.", file=sys.stderr)
        sys.exit(1)
    del vault[key]
    save_vault(vault, password)
    print(f"Secret '{key}' deleted successfully.")


def cmd_list(args):
    """List all secret keys stored in the vault."""
    password = get_password()
    vault = load_vault(password)
    if not vault:
        print("Vault is empty.")
        return
    print(f"Secrets in vault ({len(vault)}):")
    for key in sorted(vault.keys()):
        print(f"  - {key}")


def cmd_export(args):
    """Export vault secrets to stdout in various formats."""
    password = get_password()
    vault = load_vault(password)
    fmt = args.format or "env"
    if fmt == "json":
        print(json.dumps(vault, indent=2))
    elif fmt == "env":
        for key, value in vault.items():
            print(f"{key}={value}")
    elif fmt == "json-export":
        encrypted = VAULT_FILE.read_text().strip()
        print(encrypted)
    else:
        print(f"Error: Unknown format '{fmt}'. Use 'json', 'env', or 'json-export'.", file=sys.stderr)
        sys.exit(1)


def cmd_import(args):
    """Import secrets from a JSON or env-style file (unencrypted merge)."""
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"Error: File '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)
    password = get_password()
    vault = load_vault(password)
    content = filepath.read_text().strip()
    try:
        imported = json.loads(content)
    except json.JSONDecodeError:
        imported = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            imported[k.strip()] = v.strip()
    count = 0
    for k, v in imported.items():
        vault[k] = v
        count += 1
    save_vault(vault, password)
    print(f"Imported {count} secrets from {filepath}.")


def cmd_change_password(args):
    """Change the vault encryption password."""
    old_password = get_password("Current vault password")
    vault = load_vault(old_password)
    new_password = get_password("New vault password", confirm=True)
    save_vault(vault, new_password)
    print("Vault password changed successfully.")


def main():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Personal Vault CLI - Manage encrypted secrets and credentials",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_init = subparsers.add_parser("init", help="Initialize a new vault")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing vault")
    p_init.set_defaults(func=cmd_init)

    p_set = subparsers.add_parser("set", help="Store a secret")
    p_set.add_argument("key", help="Secret key name")
    p_set.add_argument("value", nargs="?", default=None, help="Secret value (prompts if omitted)")
    p_set.set_defaults(func=cmd_set)

    p_get = subparsers.add_parser("get", help="Retrieve a secret")
    p_get.add_argument("key", help="Secret key name")
    p_get.add_argument("-q", "--quiet", action="store_true", help="Print value only")
    p_get.set_defaults(func=cmd_get)

    p_delete = subparsers.add_parser("delete", aliases=["del", "rm"], help="Delete a secret")
    p_delete.add_argument("key", help="Secret key name")
    p_delete.set_defaults(func=cmd_delete)

    p_list = subparsers.add_parser("list", aliases=["ls"], help="List all secrets")
    p_list.set_defaults(func=cmd_list)

    p_export = subparsers.add_parser("export", help="Export secrets")
    p_export.add_argument("-f", "--format", choices=["json", "env", "json-export"], default="env")
    p_export.set_defaults(func=cmd_export)

    p_import = subparsers.add_parser("import", help="Import secrets from file")
    p_import.add_argument("file", help="Path to JSON or env-style file")
    p_import.set_defaults(func=cmd_import)

    p_changepw = subparsers.add_parser("change-password", aliases=["passwd"], help="Change vault password")
    p_changepw.set_defaults(func=cmd_change_password)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
