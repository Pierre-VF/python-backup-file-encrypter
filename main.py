import typer

import src

app = typer.Typer()


@app.command()
def encrypt_file(input: str, output: str | None = None):
    """Encrypt a file."""
    src.encrypt_single_file(input, output)


@app.command()
def decrypt_file(input: str, output: str | None = None):
    """Decrypt a file."""
    src.decrypt_single_file(input, output)


@app.command()
def encrypt_folder(
    root_dir: str,
    output_dir: str | None = None,
    password: str | None = None,
):
    """Encrypt a folder."""
    if output_dir is None:
        output_dir = src._SETTINGS.OUTPUT_FOLDER
    src.encrypt_all_files_in_folder(root_dir, output_dir, password=password)


@app.command()
def decrypt_folder(
    root_dir: str,
    output_dir: str | None = None,
    password: str | None = None,
):
    """Decrypts a folder."""
    src.decrypt_all_files_in_folder(root_dir, output_dir, password=password)


if __name__ == "__main__":
    app()
