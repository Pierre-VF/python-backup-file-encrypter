# python-backup-file-encrypter

This repository contains a Python file encrypter for backups.



## Installation

Installation is made witht he following steps:

1. Make sure that you have [UV](https://docs.astral.sh/uv) installed.
2. Install dependencies with `uv sync`
3. Create a `.env` file with the following content to configure password and output folder:
    ```
    ENCRYPTION_PASSWORD=your_password_here
    OUTPUT_FOLDER=choose_your_output_folder_here
    ```
4. Check your installation by running: `uv run main.py --help` (it should output a list of available commands)

## Single file operation

For operation on a single file, the commands are:

- Encrypt : `uv run main.py encrypt-file "path/to/your/file"`
- Decrypt : `uv run main.py decrypt-file "path/to/your/file"`


## File tree operation

For operation on a folder and all of its subfolders, the commands are:

- Encrypt : `uv run main.py encrypt-folder "path/to/your/folder"`
- Decrypt : `uv run main.py decrypt-folder "path/to/your/folder"`