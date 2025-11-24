"""
Secure File Storage System with AES Encryption (Project 2)

Features:
- Generate and save AES key (Fernet key)
- Encrypt any file -> .enc file
- Store metadata: original filename, size, SHA-256 hash, time
- Decrypt .enc file back to original
- Verify integrity using hash

Author: KAVURI MOHITH SAI
"""

import os
import json
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"          # stores AES key (Fernet)
META_FILE = "metadata.json"      # stores file metadata in JSON


# ---------- Utility Functions ----------

def load_or_create_key():
    """
    Load existing key from KEY_FILE.
    If not present, generate a new one and save it.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        print(f"[+] Loaded existing key from {KEY_FILE}")
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[+] Generated new key and saved to {KEY_FILE}")
    return key


def compute_sha256(data: bytes) -> str:
    """Return SHA-256 hash of given bytes as hex string."""
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()


def load_metadata():
    """Load metadata JSON file if exists else return empty list."""
    if os.path.exists(META_FILE):
        with open(META_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


def save_metadata(meta_list):
    """Save metadata list back to JSON file."""
    with open(META_FILE, "w") as f:
        json.dump(meta_list, f, indent=4)


# ---------- Core Functions ----------

def encrypt_file(file_path: str, key: bytes):
    """Encrypt the given file and save as <filename>.enc"""
    if not os.path.exists(file_path):
        print("[-] File not found!")
        return

    # Read original file bytes
    with open(file_path, "rb") as f:
        data = f.read()

    orig_size = len(data)
    file_hash = compute_sha256(data)

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    enc_file_path = file_path + ".enc"

    with open(enc_file_path, "wb") as f:
        f.write(encrypted_data)

    # Prepare metadata entry
    meta_entry = {
        "original_name": os.path.basename(file_path),
        "encrypted_name": os.path.basename(enc_file_path),
        "original_path": os.path.abspath(file_path),
        "encrypted_path": os.path.abspath(enc_file_path),
        "size_bytes": orig_size,
        "sha256": file_hash,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    metadata = load_metadata()
    metadata.append(meta_entry)
    save_metadata(metadata)

    print(f"[+] File encrypted successfully: {enc_file_path}")
    print(f"[+] Metadata stored in {META_FILE}")


def decrypt_file(enc_file_path: str, key: bytes):
    """Decrypt .enc file and restore original content."""
    if not os.path.exists(enc_file_path):
        print("[-] Encrypted file not found!")
        return

    # Read encrypted bytes
    with open(enc_file_path, "rb") as f:
        enc_data = f.read()

    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(enc_data)
    except Exception as e:
        print("[-] Decryption failed! Wrong key or corrupted file.")
        print("Error:", e)
        return

    # Try to find metadata for this file
    metadata = load_metadata()
    meta_entry = None
    for entry in metadata:
        if entry["encrypted_name"] == os.path.basename(enc_file_path):
            meta_entry = entry
            break

    # Decide output file name
    if meta_entry:
        orig_name = meta_entry["original_name"]
        expected_hash = meta_entry["sha256"]
    else:
        # Fallback if metadata missing
        print("[!] No metadata found for this file. Using default name.")
        orig_name = os.path.basename(enc_file_path).replace(".enc", "")
        expected_hash = None

    out_file_path = "DECRYPTED_" + orig_name

    with open(out_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] File decrypted and saved as: {out_file_path}")

    # Verify integrity if we have hash
    if expected_hash:
        actual_hash = compute_sha256(decrypted_data)
        if actual_hash == expected_hash:
            print("[+] Integrity check PASSED (SHA-256 matches).")
        else:
            print("[!] Integrity check FAILED (hash mismatch). File may be tampered.")


def view_metadata():
    """Display all stored metadata entries."""
    metadata = load_metadata()
    if not metadata:
        print("[-] No metadata found.")
        return

    print(f"[+] Showing metadata for {len(metadata)} file(s):")
    for idx, entry in enumerate(metadata, start=1):
        print("-" * 50)
        print(f"File #{idx}")
        print(f"Original Name : {entry['original_name']}")
        print(f"Encrypted Name: {entry['encrypted_name']}")
        print(f"Size (bytes)  : {entry['size_bytes']}")
        print(f"SHA-256 Hash  : {entry['sha256']}")
        print(f"Timestamp     : {entry['timestamp']}")
        print(f"Original Path : {entry['original_path']}")
        print(f"Encrypted Path: {entry['encrypted_path']}")
    print("-" * 50)


# ---------- Menu / Main ----------

def main():
    print("=" * 60)
    print(" SECURE FILE STORAGE SYSTEM WITH AES ENCRYPTION ")
    print("=" * 60)

    key = load_or_create_key()

    while True:
        print("\nChoose an option:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. View metadata")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            file_path = input("Enter path of file to encrypt: ").strip()
            encrypt_file(file_path, key)

        elif choice == "2":
            enc_file_path = input("Enter path of .enc file to decrypt: ").strip()
            decrypt_file(enc_file_path, key)

        elif choice == "3":
            view_metadata()

        elif choice == "4":
            print("[-] Exiting. Stay secure!")
            break
        else:
            print("[-] Invalid choice. Please select 1–4.")


if __name__ == "__main__":
    main()