import hashlib
import os
import subprocess
import sys


def sha256_string(text: str) -> str:
    """Return SHA-256 hash of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(file_path: str) -> str:
    """Return SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using a Caesar cipher."""
    result = []

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = chr((ord(char) - base + shift) % 26 + base)
            result.append(shifted)
        else:
            result.append(char)

    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt text using a Caesar cipher."""
    return caesar_encrypt(text, -shift)


def run_openssl_command(command: list[str]) -> None:
    """Run an OpenSSL command and handle errors."""
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(command)}")
        print(e)
        sys.exit(1)
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in PATH.")
        sys.exit(1)


def generate_keys(private_key="private_key.pem", public_key="public_key.pem") -> None:
    """Generate RSA private/public key pair using OpenSSL."""
    if not os.path.exists(private_key):
        run_openssl_command([
            "openssl", "genpkey",
            "-algorithm", "RSA",
            "-out", private_key,
            "-pkeyopt", "rsa_keygen_bits:2048"
        ])

    if not os.path.exists(public_key):
        run_openssl_command([
            "openssl", "rsa",
            "-pubout",
            "-in", private_key,
            "-out", public_key
        ])


def sign_file(file_path: str, private_key="private_key.pem", signature_file="signature.bin") -> None:
    """Sign a file using OpenSSL."""
    run_openssl_command([
        "openssl", "dgst",
        "-sha256",
        "-sign", private_key,
        "-out", signature_file,
        file_path
    ])


def verify_signature(file_path: str, public_key="public_key.pem", signature_file="signature.bin") -> bool:
    """Verify a file signature using OpenSSL."""
    try:
        subprocess.run([
            "openssl", "dgst",
            "-sha256",
            "-verify", public_key,
            "-signature", signature_file,
            file_path
        ], check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def main():
    # -------------------------------
    # SHA-256 STRING HASH DEMO
    # -------------------------------
    input_text = "Hello, cybersecurity world!"
    string_hash = sha256_string(input_text)

    print("=== SHA-256 STRING HASH ===")
    print(f"Input string: {input_text}")
    print(f"SHA-256 hash: {string_hash}\n")

    # -------------------------------
    # SHA-256 FILE HASH DEMO
    # -------------------------------
    sample_file = "sample.txt"
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write("This is a sample file for SHA-256 hashing and signing.")

    file_hash = sha256_file(sample_file)

    print("=== SHA-256 FILE HASH ===")
    print(f"File: {sample_file}")
    print(f"SHA-256 hash: {file_hash}\n")

    # -------------------------------
    # CAESAR CIPHER DEMO
    # -------------------------------
    plain_text = "Attack at Dawn!"
    shift_value = 3
    encrypted_text = caesar_encrypt(plain_text, shift_value)
    decrypted_text = caesar_decrypt(encrypted_text, shift_value)

    print("=== CAESAR CIPHER ===")
    print(f"Plaintext:  {plain_text}")
    print(f"Shift:      {shift_value}")
    print(f"Encrypted:  {encrypted_text}")
    print(f"Decrypted:  {decrypted_text}\n")

    # -------------------------------
    # DIGITAL SIGNATURE DEMO
    # -------------------------------
    print("=== DIGITAL SIGNATURE WITH OPENSSL ===")
    generate_keys()
    sign_file(sample_file)

    is_valid = verify_signature(sample_file)

    print(f"Private key: private_key.pem")
    print(f"Public key:  public_key.pem")
    print(f"Signature:   signature.bin")
    print(f"Verification result: {'VALID' if is_valid else 'INVALID'}")


if __name__ == "__main__":
    main()