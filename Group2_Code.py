# This is the running effort for the document.
# print("Hello Group2")
# print("Welcome To Wk4")

# To run this code access terminal from the menu in GitHub.
# To do this first click on "Code Spaces" in the Navigation Bar
# Add you edits there.
# In the GitHub Terminal type: python3 Group2_Code.py
# This is the difficult part:
# to save your changes to GitHub you will need to use the following commands:
# git add .
# git commit -m "Your Message Here"
# git push

# ── Group2_Code.py — Encrypted Probability Journal (CLI) ──
# Logs encounters with a success probability, stores history as CSV text,
# and keeps it encrypted on disk (journal.enc) using a password.
# Password basics:
# - First run: you create a password; the journal is encrypted with it.
# - Later runs: you must enter the SAME password to decrypt journal.enc.
# - Wrong password: the app reprompts (it never overwrites the file).
# - Change password: re-encrypts the existing data with the new password.
# - Reset journal: deletes journal.enc (data is unrecoverable).
# - If you forget the password, the data cannot be recovered.
#
# Quick start:
# 1) (Recommended) Create a venv:
#      python -m venv .venv
#      # Activate:  .venv\Scripts\activate  (Windows)
#      #            source .venv/bin/activate (macOS/Linux)
# 2) Install deps:  pip install -r requirements.txt
# 3) Run:           python Group2_Code.py
#    - First run: set a password (creates a new encrypted journal).
#    - Later runs: enter the same password to decrypt and continue.


from __future__ import annotations

import csv, os, json, base64, getpass
import random  # for probability calculation
from dataclasses import dataclass
from math import prod
from datetime import datetime
from io import StringIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # key derivation
from cryptography.hazmat.primitives import hashes

JOURNAL_ENC = "journal.enc"
CSV_HEADER = [
    "timestamp",
    "character",
    "encounter",
    "probability",
    "damage",
    "outcome",
    "algo",
    "note",
]


def parse_prob(s: str) -> float:
    """
    Parse user input probability into a float in [0, 1].

    Accepts:
      - Decimal form: '0.7'
      - Percent form: '70%'

    Raises:
      ValueError if not a number or outside [0, 1].
    """

    s = s.strip()
    is_pct = s.endswith("%")
    if is_pct:
        s = s[:-1]

    p = float(s)
    if is_pct:
        p /= 100.0

    if not (0.0 <= p <= 1.0):
        raise ValueError("Probability must be 0–1.")

    return p


def load_csv_from_encrypted(password: str) -> list[dict]:
    """
    Read the encrypted journal from JOURNAL_ENC using the given password.

    Flow:
      1) Read JSON blob {salt, ciphertext}.
      2) Derive key from password+salt (PBKDF2).
      3) Decrypt with Fernet (verifies integrity).
      4) Parse CSV text into a list of dict rows.

    Returns [] on first run (no file).
    """
    if not os.path.exists(JOURNAL_ENC):
        return []
    with open(JOURNAL_ENC, "r", encoding="utf-8") as f:
        blob = json.load(f)
    plaintext = _decrypt_bytes(password, blob).decode("utf-8")
    return list(csv.DictReader(plaintext.splitlines()))


def save_csv_to_encrypted(password: str, rows: list[dict]) -> None:
    """
    Serialize rows → CSV text → encrypt → write JOURNAL_ENC.

    Using authenticated encryption (Fernet) ensures the file cannot be
    modified without detection and keeps the contents confidential.
    """
    sio = StringIO()
    writer = csv.DictWriter(sio, fieldnames=CSV_HEADER)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    plaintext = sio.getvalue().encode("utf-8")
    blob = _encrypt_bytes(password, plaintext)
    with open(JOURNAL_ENC, "w", encoding="utf-8") as f:
        json.dump(blob, f)


def cumulative_for_character(rows: list[dict], name: str) -> float:
    """
    Calculates the character's overall survival score by multiplying the probabilities of all their past encounters.

    This represents an "HP-style" survival meter: each logged encounter reduces total survival proportionally based on its
    probability result.
    """
    vals = [
        float(r["probability"])
        for r in rows
        if r["character"] == name and r.get("algo") not in ("meta", "config")
    ]
    return prod(vals) if vals else 1.0


def compute_hp(rows: list[dict], name: str, start_hp: float = 100.0) -> float:
    """Apply each encounter as a Bernoulli trial:
    if outcome=='hit' → hp -= damage; else unchanged. Ignores meta/config."""
    seq = [
        r
        for r in rows
        if r["character"] == name and r.get("algo") not in ("meta", "config")
    ]
    seq.sort(key=lambda r: r["timestamp"])
    hp = float(start_hp)
    for r in seq:
        dmg = float(r.get("damage", 0) or 0)
        if (r.get("outcome") or "").lower() == "hit":
            hp = max(0.0, hp - dmg)
    return hp


def hp_fraction(rows: list[dict], name: str, start_hp: float = 100.0) -> float:
    return compute_hp(rows, name, start_hp) / start_hp if start_hp > 0 else 0.0


def hp_bar(hp: float, width: int = 20) -> str:
    """
    Returns a color-coded HP bar based on a decimal HP value.
    hp: A float between 0 and 1 (e.g. 0.75 = 75% HP)
    width: Total width of the bar display
    """
    # Determines how much of the bar is full vs empty
    filled = int(hp * width)
    empty = width - filled

    # Colors - HP bar changes color depending on how full or low it is
    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    reset = "\033[0m"

    if hp >= 0.6:
        color = green
    elif hp >= 0.3:
        color = yellow
    else:
        color = red

    bar = f"{color}[{'█' * filled}{'░' * empty}]{reset} {hp * 100:.1f}%"
    return bar


def total_survival(rows: list[dict]) -> float:
    """
    Compute the cumulative survival as the product of probabilities.
    If no rows yet, return 1.0 (neutral element for multiplication).
    """
    return prod(float(r["probability"]) for r in rows) if rows else 1.0


def print_history(rows: list[dict], name: str) -> None:
    hist = [
        r
        for r in rows
        if r["character"] == name and r.get("algo") not in ("meta", "config")
    ]
    if not hist:
        print(f"No entries for '{name}'.")
        return
    hist.sort(key=lambda r: r["timestamp"])

    hp = 100.0
    print(f"\nHistory for {name}")
    print("timestamp              encounter            prob   dmg  outcome  hp_after")
    for r in hist:
        p = float(r["probability"])
        dmg = float(r.get("damage", 0) or 0)
        outcome = (r.get("outcome") or "").lower()
        if outcome == "hit":
            hp = max(0.0, hp - dmg)
        enc = (r.get("encounter", "") or "")[:20]
        bar = hp_bar(hp / 100.0, width=20)
        print(
            f"{r['timestamp']:20s}  {enc:20s}  {p:0.3f}  {dmg:4.0f}  {outcome:7s}  {bar}"
        )
    print(f"Final HP: {hp:0.1f}\n")


def list_encounter_types(rows: list[dict]) -> None:
    """
    Print all unique encounter types recorded across all characters.
    """
    # Collect all encounter names
    types = {r["encounter"].lower() for r in rows if r.get("algo") != "meta"}

    if not types:
        print("No encounter types logged yet.")
    else:
        print("\nKnown Encounter Types:")
        for t in sorted(types):
            print(f"- {t}")
        print()


def avg_prob_for_type(rows: list[dict], encounter_type: str):
    """
    Calculates average survival probability of a specific Encounter Type.
    Returns average probability and number of instances of the Encounter Type.
    """
    probs = [
        float(r["probability"])
        for r in rows
        if r.get("encounter", "").lower() == encounter_type.lower()
        and r.get("algo") != "meta"
    ]
    if not probs:
        return None, 0

    avg = sum(probs) / len(probs)
    return avg, len(probs)


def sample_prob(encounter_name: str) -> float:
    return random.uniform(0.55, 0.85)


def _norm(name: str) -> str:
    return name.strip().lower()


def load_fixed_map(rows: list[dict]) -> dict[str, float]:
    """
    Scan meta rows (algo='config') like: note='fixed|encounter=<name>|p=<value>'
    Returns {encounter_name_lower: p}
    """
    fixed: dict[str, float] = {}
    for r in rows:
        if r.get("algo") == "config" and r.get("note", "").startswith("fixed|"):
            # format: fixed|encounter=<name>|p=<value>
            parts = dict(seg.split("=", 1) for seg in r["note"].split("|")[1:])
            name = _norm(parts.get("encounter", ""))
            if name and "p" in parts:
                try:
                    fixed[name] = float(parts["p"])
                except ValueError:
                    pass
    return fixed


def set_fixed_prob(rows: list[dict], encounter_name: str, p: float) -> None:
    """
    Append a meta config row for a fixed probability, persisted in the journal.
    """
    rows.append(
        {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "character": "",  # global config, not tied to a character
            "encounter": encounter_name,  # optional; kept for readability
            "probability": "1.0",  # neutral
            "algo": "config",
            "note": f"fixed|encounter={encounter_name}|p={p:.6f}",
        }
    )


def clear_character(rows: list[dict], name: str) -> int:
    """
    In-place filter of `rows` to drop encounters for `name`.
    Returns the number of removed rows. Caller is responsible for saving.
    """
    before = len(rows)
    rows[:] = [r for r in rows if r["character"] != name or r.get("algo") == "meta"]
    return before - len(rows)


def change_password(old_pwd: str, rows: list[dict]) -> str:
    """
    Optional 'verify current password' step + set a new password.
    Re-encrypts the already-decrypted `rows` with the new password and saves.
    Returns the new password on success, "" on failure.
    """
    check = getpass.getpass("Current password: ")
    if check != old_pwd:
        print("Incorrect current password.")
        return ""
    p1 = getpass.getpass("New password: ")
    p2 = getpass.getpass("Confirm new password: ")
    if not p1 or p1 != p2:
        print("Passwords did not match.")
        return ""
    save_csv_to_encrypted(p1, rows)
    print("Password updated.")
    return p1


def unique_characters(rows: list[dict]) -> list[str]:
    names = {
        r["character"] for r in rows if r.get("algo") != "meta" and r.get("character")
    }
    return sorted(names)


def character_summaries(rows: list[dict]) -> list[tuple[str, float, int]]:
    by_name: dict[str, list[float]] = {}
    for r in rows:
        if r.get("algo") == "meta":
            continue
        name = r["character"]
        by_name.setdefault(name, []).append(float(r["probability"]))
    out: list[tuple[str, float, int]] = []
    for name, probs in by_name.items():
        total = 1.0
        for p in probs:
            total *= p
        out.append((name, total, len(probs)))
    # sort by name; change key if you prefer highest total first: key=lambda t: -t[1]
    return sorted(out, key=lambda t: t[0])


def print_names(rows: list[dict]) -> None:
    names = unique_characters(rows)
    if not names:
        print("No characters found.")
        return
    print("\nCharacters:")
    for n in names:
        print(f"- {n}")
    print()


def print_character_summaries(rows: list[dict]) -> None:
    summaries = character_summaries(rows)
    if not summaries:
        print("No character data to summarize.")
        return
    print("\nCharacter Summary")
    print("name                 entries   cumulative   hp(100→)         ")
    for name, total, count in summaries:
        hp_pts = compute_hp(rows, name, 100.0)
        bar = hp_bar(hp_pts / 100.0, width=14)
        print(f"{name:20s}   {count:7d}   {total:0.3f}   {hp_pts:6.1f}  {bar}")
    print()


def reset_journal() -> bool:
    """
    Safely remove journal.enc after a typed confirmation.
    Does not modify in-memory `rows`; caller should clear those.
    """
    confirm = input('Type "DELETE" to permanently remove journal.enc: ').strip()
    if confirm != "DELETE":
        print("Reset canceled.")
        return False
    try:
        os.remove(JOURNAL_ENC)
        print("journal.enc removed.")
        return True
    except FileNotFoundError:
        print("No journal to remove.")
        return False


def open_or_create_journal() -> tuple[list[dict], str]:
    """
    If journal.enc exists: loop until a valid password decrypts it (or user cancels).
    If it doesn't: ask the user to create/confirm a new password; start empty.
    Returns (rows, password). If canceled, returns ([], "").
    """
    if os.path.exists(JOURNAL_ENC):
        while True:
            pwd = getpass.getpass("Enter journal password (Enter to cancel): ")
            if not pwd:
                print("Canceled.")
                return [], ""
            try:
                rows = load_csv_from_encrypted(pwd)
                return rows, pwd
            except Exception:
                print("Wrong password or corrupt file. Try again.")
    else:
        while True:
            p1 = getpass.getpass("Create a new password: ")
            p2 = getpass.getpass("Confirm password: ")
            if p1 and p1 == p2:
                print("New journal created.")
                return [], p1
            print("Passwords did not match. Try again.")


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from a human password using PBKDF2-HMAC-SHA256.
    - salt: 16 bytes random per journal file
    - iterations: 200k (good classroom default)
    Returns a base64-url key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _encrypt_bytes(password: str, plaintext: bytes, salt: bytes | None = None) -> dict:
    """
    Encrypt arbitrary bytes with a password.
    Returns a JSON-serializable dict: {'salt': b64, 'ciphertext': b64}.
    """
    salt = os.urandom(16) if salt is None else salt
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext)
    return {
        "salt": base64.b64encode(salt).decode(),
        "ciphertext": base64.b64encode(token).decode(),
    }


def _decrypt_bytes(password: str, blob: dict) -> bytes:
    """
    Reverse of _encrypt_bytes. Raises if password is wrong or data is tampered.
    """
    salt = base64.b64decode(blob["salt"])
    token = base64.b64decode(blob["ciphertext"])
    key = _derive_key(password, salt)
    return Fernet(key).decrypt(token)


def collect_user_profile() -> UserProfile:
    """
    One-time prompt when the journal is empty.
    Stores minimal user metadata as a 'meta' row inside the encrypted file.
    """
    name = input("Profile name (press Enter to reuse character name later): ").strip()
    location = input("Location (optional): ").strip()
    email = input("Contact email (optional): ").strip()
    return UserProfile(name=name or "", location=location, email=email)


@dataclass
class Encounter:
    """
    Represents one logged encounter.
    - timestamp: ISO 8601 string
    - character: which character the encounter belongs to
    - probability: success probability (0–1) after any algorithm transform
    - algo: algorithm name used to compute the stored probability
    """

    timestamp: str
    character: str
    encounter: str
    probability: float
    algo: str = "basic"
    note: str = ""


@dataclass
class UserProfile:
    name: str
    location: str = ""
    email: str = ""


def main() -> None:
    """
    App entrypoint: open/create the encrypted journal, ensure first-run profile,
    then run a simple menu so the user can:
      - Add an encounter (validate prob; save encrypted)
      - List known encounter types (user can choose from known encounter type or enter new encounter type)
      - List a characters history with running total
      - Clear a characters entries
      - Change the journal password (re-encrypt in place)
      - Reset (delete) the journal file
      - Quit
    All calculations come from the persisted (decrypted) rows in memory.
    """
    print("Welcome to Group 2 MVP")

    rows, password = open_or_create_journal()
    if not password:
        return

    if not rows:
        profile = collect_user_profile()
        rows.append(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "character": profile.name or "default",
                "probability": "1.0",
                "algo": "meta",
                "note": f"profile|location={profile.location}|email={profile.email}",
            }
        )
        save_csv_to_encrypted(password, rows)

    while True:
        print(
            "\nMenu: [A]dd Encounter [E]ncounter Types  [L]ist History  [N]ames  [S]ummary  "
            "[C]lear Character  [P]asswd Change  [R]eset Journal  [Q]uit"
        )
        choice = input("> ").strip().lower()

        if choice == "a":  # Add encounter
            name = input("Character name: ").strip()
            if not name:
                print("Name required.")
                continue

            enc_name = input("Encounter name: ").strip() or "unspecified"

            # ---- choose probability mode (Fixed or Random) ----
            mode = input("Probability mode [F]ixed / [R]andom? ").strip().lower()
            fixed_map = load_fixed_map(rows)  # requires helper
            key = _norm(enc_name)  # requires helper

            if mode == "f":
                if key in fixed_map:
                    p = fixed_map[key]
                    print(f"Using saved fixed p={p:.3f} for '{enc_name}'.")
                else:
                    while True:
                        raw = input("Set fixed probability (0.0–1.0): ").strip()
                        try:
                            p = float(raw)
                            if 0.0 <= p <= 1.0:
                                break
                        except ValueError:
                            pass
                        print("Invalid. Enter a number between 0 and 1.")
                    set_fixed_prob(rows, enc_name, p)  # persist fixed p as meta row
                    save_csv_to_encrypted(password, rows)
                    print(f"Saved fixed p={p:.3f} for '{enc_name}'.")
                algo_label = "fixed"
            else:
                p = sample_prob(enc_name)  # requires helper + _rng
                algo_label = "random"

            # ---- damage ----
            while True:
                raw_dmg = input("Damage this encounter (0 for none): ").strip() or "0"
                try:
                    dmg = float(raw_dmg)
                    if dmg >= 0:
                        break
                except ValueError:
                    pass
                print("Invalid. Enter a number ≥ 0.")

            # ---- run Bernoulli(p) to decide hit/miss, then apply damage on hit ----
            curr_hp = compute_hp(rows, name, 100.0)  # requires helper
            hit = random.random() < p
            outcome = "hit" if hit else "miss"
            new_hp = max(0.0, curr_hp - (dmg if hit else 0.0))

            # ---- record encounter ----
            ts = datetime.now().isoformat(timespec="seconds")
            rows.append(
                {
                    "timestamp": ts,
                    "character": name,
                    "encounter": enc_name,
                    "probability": f"{p:.6f}",
                    "damage": f"{dmg:.2f}",
                    "outcome": outcome,  # NEW
                    "algo": algo_label,  # "fixed" or "random"
                    "note": "",
                }
            )
            save_csv_to_encrypted(password, rows)

            # ---- feedback ----
            bar = hp_bar(new_hp / 100.0, width=20)  # requires your hp_bar()
            print(
                f"Result: {outcome.upper()} | p={p:.3f}, dmg={dmg:.0f} | HP {new_hp:0.1f}"
            )
            print(bar)

        elif choice == "e":  # List known encounter types
            list_encounter_types(rows)

        elif choice == "l":  # List history
            name = input("Character to list: ").strip()
            print_history(rows, name)

        elif choice == "n":  # list names only
            print_names(rows)

        elif choice == "s":  # list names with cumulative probability and entry count
            print_character_summaries(rows)

        elif choice == "c":  # Clear character entries
            name = input("Character to clear: ").strip()
            confirm = input(f'Type "YES" to clear all entries for {name}: ').strip()
            if confirm == "YES":
                removed = clear_character(rows, name)
                save_csv_to_encrypted(password, rows)
                print(f"Removed {removed} entries.")
            else:
                print("Canceled.")

        elif choice == "p":  # Change password
            new_pwd = change_password(password, rows)
            if new_pwd:
                password = new_pwd

        elif choice == "r":  # Reset journal file
            if reset_journal():
                rows.clear()
                print("Journal cleared. Relaunch to create a new one.")
                break

        elif choice == "q":  # Quit
            break

        else:
            print("Choose A/E/L/N/S/C/P/R/Q.")


if __name__ == "__main__":
    main()
