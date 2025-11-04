# This is the running effort for the document.
# print("Hello Group2")
# print("Welcome To Wk4")

# To run this code access terminal from the menu in GitHub.
# To do this first click on "Code Spaces" in the Navigation Bar
# Add you edits there.
# In the GitHub Termanl type: python3 Group2_Code.py
# This is the difficult part:
# to save your changes to GitHub you will need to use the following commands:
# git add .
# git commit -m "Your Message Here"
# git push

# ── Group2_Code.py — Encrypted Probability Journal (CLI) ──
# Logs encounters with a success probability, stores history as CSV text,
# and keeps it encrypted on disk (journal.enc) using a password.
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
from dataclasses import dataclass
from math import prod
from datetime import datetime
from io import StringIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # key derivation
from cryptography.hazmat.primitives import hashes

JOURNAL_ENC = "journal.enc"
CSV_HEADER = ["timestamp", "character", "probability", "algo", "note"]


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
    Compute product of probabilities for the specified character
    using ONLY the persisted (decrypted) rows.
    """
    vals = [float(r["probability"]) for r in rows if r["character"] == name]
    return prod(vals) if vals else 1.0


def total_survival(rows: list[dict]) -> float:
    """
    Compute the cumulative survival as the product of probabilities.
    If no rows yet, return 1.0 (neutral element for multiplication).
    """
    return prod(float(r["probability"]) for r in rows) if rows else 1.0


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
    probability: float
    algo: str = "basic"
    note: str = ""


@dataclass
class UserProfile:
    name: str
    location: str = ""
    email: str = ""


def main():
    """
    Interactive flow:
      1) Ask for password and open (decrypt) the journal.
      2) If new journal, collect a minimal user profile (encrypted meta row).
      3) Prompt for character and probability.
      4) Append encounter to in-memory rows.
      5) Re-encrypt and save; compute cumulative total from FILE rows.
      6) Print a short summary.
    """
    print("Welcome to Group 2 MVP")

    password = getpass.getpass("Enter journal password: ").strip()
    try:
        rows = load_csv_from_encrypted(password)
    except Exception:
        print("Error: could not decrypt journal. Wrong password or corrupt file.")
        return

    if not rows:
        print("No prior entries found. (New journal)")
        profile = collect_user_profile()
        # store profile as a synthetic row with note (keeps CSV simple)
        rows.append(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "character": profile.name or "default",
                "probability": "1.0",
                "algo": "meta",
                "note": f"profile|location={profile.location}|email={profile.email}",
            }
        )

    while True:
        character_name = input("Enter Character Name: ").strip()
        if character_name:
            break
        print("Please enter a non-empty name.")

    while True:
        raw = input("Enter Probability (e.g., 0.7 or 70%): ").strip()
        try:
            p = parse_prob(raw)
            break
        except ValueError as e:
            print(f"Invalid. Enter 0.00–1.00 or 0–100%. ({e})")

    enc = Encounter(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        character=character_name,
        probability=p,
        algo="basic",
        note="",
    )
    rows.append(
        {
            "timestamp": enc.timestamp,
            "character": enc.character,
            "probability": f"{enc.probability:.6f}",
            "algo": enc.algo,
            "note": enc.note,
        }
    )

    save_csv_to_encrypted(password, rows)
    cumulative = cumulative_for_character(rows, character_name)

    # 5) Output
    print("\n--- Entry Recorded (encrypted) ---")
    print(f"time:      {enc.timestamp}")
    print(f"name:      {character_name}")
    print(f"p (0–1):   {p:.3f}")
    print(f"overall:   {cumulative:.3f}")


if __name__ == "__main__":
    main()
