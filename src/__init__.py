import os
import os.path
from pathlib import Path
from typing import Generator

import typer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# ------------------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------------------


class Settings(BaseSettings):
    ENCRYPTION_PASSWORD: str
    OUTPUT_FOLDER: str = "output"


load_dotenv()
_SETTINGS = Settings()

# ------------------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------------------


class WrongPasswordError(ValueError):
    pass


# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------
def derive_key(password: str | None, salt: bytes) -> bytes:
    """Derive a secure encryption key from a password and salt."""
    if password is None:
        password = _SETTINGS.ENCRYPTION_PASSWORD
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def _default_output(input_path: str, output_path: str | None) -> str:
    if output_path is None:
        out = str(Path(_SETTINGS.OUTPUT_FOLDER) / input_path) + ".enc"
        if out.endswith(".enc"):
            # Remove the .enc if present
            return out[:-4]
        else:
            # Add the .enc if present
            return out + ".enc"

    else:
        return output_path


def encrypt_single_file(
    input_path: str,
    output_path: str | None = None,
    password: str | None = None,
):
    """Encrypt a file using AES-GCM."""
    output_path = _default_output(input_path, output_path)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    typer.echo(f"File encrypted and saved to {output_path}")


def decrypt_single_file(
    input_path: str,
    output_path: str | None = None,
    password: str | None = None,
):
    """Decrypt a file using AES-GCM."""
    output_path = _default_output(input_path, output_path)
    with open(input_path, "rb") as f:
        data = f.read()

    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        typer.echo(f"Decryption failed: {e}")
        raise WrongPasswordError(f"Decryption failed: {e}")

    output_folder = Path(output_path).parent
    if not os.path.isdir(output_folder):
        os.makedirs(output_folder, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    typer.echo(f"File decrypted and saved to {output_path}")
    return True


def folder_files_generator(
    folder: str,
    output_dir: str | None = None,
) -> Generator[tuple[str, str], None, None]:
    for root, _, files in os.walk(folder):
        for file in files:
            input_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_path, folder)
            output_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            yield (input_path, output_path)


def encrypt_all_files_in_folder(
    root_dir: str,
    output_dir: str | None,
    password: str | None = None,
):
    if output_dir is None:
        output_dir = _SETTINGS.OUTPUT_FOLDER
    for i, j in folder_files_generator(root_dir, output_dir=output_dir):
        j = j + ".enc"
        encrypt_single_file(i, j, password=password)
        typer.echo(f"Encrypted: {i} -> {j}")


def decrypt_all_files_in_folder(
    root_dir: str,
    output_dir: str | None,
    password: str | None = None,
):
    if output_dir is None:
        output_dir = _SETTINGS.OUTPUT_FOLDER
    for i, j in folder_files_generator(root_dir, output_dir=output_dir):
        j = j[:-4]  # Remove '.enc'
        if decrypt_single_file(i, j, password=password):
            typer.echo(f"Decrypted: {i} -> {j}")
