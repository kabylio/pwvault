"""Interactive command-line interface."""
from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

from .generator import generate_password
from .legacy import read_legacy
from .vault import (Entry, InvalidMasterPassword, Vault, VaultError,
                    WeakPasswordError, validate_master_password)

DEFAULT_PATH = Path.home() / ".pwvault" / "vault.db"
MAX_ATTEMPTS = 3

MENU = """
 1. Add an entry
 2. Show an entry
 3. List / search entries
 4. Update an entry
 5. Delete an entry
 6. Generate a password
 7. Change master password
 8. Import from old prototype (key + password file)
 9. Quit
"""


def ask_new_master() -> str:
    while True:
        first = getpass.getpass("Choose a master password: ")
        try:
            validate_master_password(first)
        except WeakPasswordError as exc:
            print(f"  ! {exc}")
            continue
        if first != getpass.getpass("Confirm master password: "):
            print("  ! Passwords do not match.")
            continue
        return first


def unlock(path: Path) -> Vault | None:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return Vault.open(path, getpass.getpass("Master password: "))
        except InvalidMasterPassword:
            print(f"  ! Wrong master password ({attempt}/{MAX_ATTEMPTS})")
            time.sleep(attempt)  # simple slowdown against guessing
    return None


def pick(vault: Vault, prompt: str = "Search: ") -> Entry | None:
    matches = vault.find(input(prompt))
    if not matches:
        print("  No matching entries.")
        return None
    if len(matches) == 1:
        return matches[0]
    for i, e in enumerate(matches, 1):
        print(f"  {i}. {e.site}  ({e.username or '-'})")
    choice = input("Number: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(matches):
        return matches[int(choice) - 1]
    print("  Invalid choice.")
    return None


def ask_password() -> str:
    pw = getpass.getpass("Password (leave empty to generate one): ")
    if pw:
        return pw
    pw = generate_password()
    print(f"  Generated: {pw}")
    return pw


def action_add(v: Vault) -> None:
    site = input("Site: ").strip()
    if not site:
        print("  ! Site is required.")
        return
    v.add_entry(site, input("Username: "), ask_password(), input("Notes: "))
    print(f"  Saved '{site}'.")


def action_show(v: Vault) -> None:
    e = pick(v)
    if e:
        print(f"\n  Site:     {e.site}\n  Username: {e.username}\n"
              f"  Password: {e.password}\n  Notes:    {e.notes}\n"
              f"  Updated:  {e.updated_at}")


def action_list(v: Vault) -> None:
    entries = v.find(input("Filter (empty = all): "))
    for e in entries:
        print(f"  - {e.site}  ({e.username or '-'})")
    print(f"  {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}.")


def action_update(v: Vault) -> None:
    e = pick(v)
    if not e:
        return
    print("  Press Enter to keep the current value.")
    changes = {}
    for field in ("site", "username", "notes"):
        value = input(f"{field.capitalize()} [{getattr(e, field)}]: ")
        if value:
            changes[field] = value
    pw = getpass.getpass("New password (Enter = keep, 'gen' = generate): ")
    if pw == "gen":
        pw = generate_password()
        print(f"  Generated: {pw}")
    if pw:
        changes["password"] = pw
    if changes:
        v.update_entry(e.id, **changes)
        print("  Updated.")


def action_delete(v: Vault) -> None:
    e = pick(v)
    if e and input(f"Delete '{e.site}'? Type 'yes': ").strip() == "yes":
        v.delete_entry(e.id)
        print("  Deleted.")


def action_generate(_: Vault) -> None:
    raw = input("Length [20]: ").strip()
    print("  " + generate_password(int(raw) if raw.isdigit() else 20))


def action_change_master(v: Vault) -> None:
    old = getpass.getpass("Current master password: ")
    try:
        v.change_master_password(old, ask_new_master())
        print("  Master password changed.")
    except InvalidMasterPassword:
        print("  ! Current master password is wrong.")


def action_import(v: Vault) -> None:
    key = input("Path to old key file: ").strip()
    data = input("Path to old password file: ").strip()
    try:
        items = read_legacy(key, data)
    except (OSError, ValueError) as exc:
        print(f"  ! {exc}")
        return
    for site, pw in items.items():
        v.add_entry(site, "", pw, "imported from prototype")
    print(f"  Imported {len(items)} entries. Delete the old key and password "
          "files securely now.")


ACTIONS = {"1": action_add, "2": action_show, "3": action_list,
           "4": action_update, "5": action_delete, "6": action_generate,
           "7": action_change_master, "8": action_import}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pwvault", description=__doc__)
    parser.add_argument("--vault", type=Path, default=DEFAULT_PATH,
                        help=f"vault file (default: {DEFAULT_PATH})")
    path = parser.parse_args(argv).vault

    if path.exists():
        vault = unlock(path)
        if vault is None:
            sys.exit("Too many failed attempts.")
    else:
        print(f"No vault found at {path}. Let's create one.")
        vault = Vault.create(path, ask_new_master())
        print("Vault created. Do not forget your master password: it cannot "
              "be recovered.")

    with vault:
        while True:
            print(MENU)
            choice = input("Choice: ").strip()
            if choice == "9":
                break
            action = ACTIONS.get(choice)
            if not action:
                print("  Invalid choice.")
                continue
            try:
                action(vault)
            except (VaultError, ValueError, KeyError) as exc:
                print(f"  ! {exc}")
    print("Vault locked. Goodbye.")
