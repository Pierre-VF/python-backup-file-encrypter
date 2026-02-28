import os
import os.path
from pathlib import Path

import typer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ENCRYPTION_PASSWORD: str
    OUTPUT_FOLDER: str = "output"


load_dotenv()
_SETTINGS = Settings()

app = typer.Typer()


def _derive_key(salt: bytes) -> bytes:
    """Derive a secure encryption key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(_SETTINGS.ENCRYPTION_PASSWORD.encode())


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


def _encrypt_single_file(input_path: str, output_path: str | None = None):
    """Encrypt a file using AES-GCM."""
    output_path = _default_output(input_path, output_path)
    salt = os.urandom(16)
    key = _derive_key(salt)
    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    typer.echo(f"File encrypted and saved to {output_path}")


def _decrypt_single_file(input_path: str, output_path: str | None = None):
    """Decrypt a file using AES-GCM."""
    output_path = _default_output(input_path, output_path)
    with open(input_path, "rb") as f:
        data = f.read()

    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = _derive_key(salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        typer.echo(f"Decryption failed: {e}")
        raise typer.Exit(1)

    output_folder = Path(output_path).parent
    if not os.path.isdir(output_folder):
        os.makedirs(output_folder, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    typer.echo(f"File decrypted and saved to {output_path}")


@app.command()
def encrypt_file(input: str, output: str | None = None):
    """Encrypt a file."""
    _encrypt_single_file(input, output)


@app.command()
def decrypt_file(input: str, output: str | None = None):
    """Decrypt a file."""
    _decrypt_single_file(input, output)


def _util_folder_loop(
    root_dir: str,
    output_dir: str,
    encrypt: bool,
) -> None:
    for root, _, files in os.walk(root_dir):
        for file in files:
            input_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_path, root_dir)
            output_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            if encrypt:
                encrypt_file(input_path, output_path + ".enc")
                typer.echo(f"Encrypted: {input_path} -> {output_path}.enc")
            else:
                if file.endswith(".enc"):
                    output_path = output_path[:-4]  # Remove '.enc'
                    if decrypt_file(input_path, output_path):
                        typer.echo(f"Decrypted: {input_path} -> {output_path}")


@app.command()
def encrypt_folder(root_dir: str, output_dir: str | None = None):
    """Encrypt a folder."""
    if output_dir is None:
        output_dir = _SETTINGS.OUTPUT_FOLDER
    _util_folder_loop(root_dir, output_dir, encrypt=True)


@app.command()
def decrypt_folder(root_dir: str, output_dir: str | None = None):
    """Decrypts a folder."""
    if output_dir is None:
        output_dir = _SETTINGS.OUTPUT_FOLDER
    _util_folder_loop(root_dir, output_dir, encrypt=False)


if __name__ == "__main__":
    app()
