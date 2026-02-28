import os
import tempfile
import unittest

from src import (
    WrongPasswordError,
    decrypt_single_file,
    derive_key,
    encrypt_single_file,
    util_folder_loop,
)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.test_password = "testpassword"
        self.test_salt = os.urandom(16)
        self.test_key = derive_key(self.test_password, self.test_salt)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_derive_key(self):
        key1 = derive_key(self.test_password, self.test_salt)
        key2 = derive_key(self.test_password, self.test_salt)
        self.assertEqual(key1, key2)
        self.assertNotEqual(key1, derive_key("wrongpassword", self.test_salt))

    def test_encrypt_decrypt_single_file(self):
        test_content = b"Hello, world!"
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        decrypted_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        with open(input_path, "wb") as f:
            f.write(test_content)

        encrypt_single_file(input_path, encrypted_path, self.test_password)
        self.assertTrue(os.path.exists(encrypted_path))
        # Check that initial file still exists
        self.assertTrue(os.path.exists(input_path))

        result = decrypt_single_file(encrypted_path, decrypted_path, self.test_password)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(decrypted_path))

        with open(decrypted_path, "rb") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_content)

    def test_wrong_password(self):
        test_content = b"Hello, world!"
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        decrypted_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        with open(input_path, "wb") as f:
            f.write(test_content)

        encrypt_single_file(input_path, encrypted_path, self.test_password)
        try:
            result = decrypt_single_file(
                encrypted_path, decrypted_path, "wrongpassword"
            )
            self.assertFalse(result)
        except WrongPasswordError:
            pass  # Error should be triggered

    def test_process_files_encrypt_decrypt(self):
        # Create a nested structure
        subdir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(subdir)
        test_files = [
            os.path.join(self.temp_dir, "file1.txt"),
            os.path.join(subdir, "file2.txt"),
        ]
        for file in test_files:
            with open(file, "wb") as f:
                f.write(b"Test data")

        # Encrypt all
        encrypted_dir = os.path.join(self.temp_dir, "encrypted")
        util_folder_loop(
            self.temp_dir,
            encrypted_dir,
            encrypt=True,
            password=self.test_password,
        )
        for root, _, files in os.walk(encrypted_dir):
            for file in files:
                self.assertTrue(file.endswith(".enc"))

        # Decrypt all
        decrypted_dir = os.path.join(self.temp_dir, "decrypted")
        util_folder_loop(
            encrypted_dir,
            decrypted_dir,
            encrypt=False,
            password=self.test_password,
        )
        for root, _, files in os.walk(decrypted_dir):
            for file in files:
                self.assertFalse(file.endswith(".enc"))
                with open(os.path.join(root, file), "rb") as f:
                    content = f.read()
                self.assertEqual(content, b"Test data")


if __name__ == "__main__":
    unittest.main()
