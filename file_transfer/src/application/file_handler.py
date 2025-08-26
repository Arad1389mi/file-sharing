# FileName: MultipleFiles/file_handler.py
# FileContents:
import os
from RSA import RSACrypto

class FileHandler:
    def __init__(self, key_size=2048):
        self.rsa = RSACrypto()
        self.chunk_size = 214  # Max bytes RSA-2048 can encrypt
        self.public_key, self.private_key = self.rsa.generateKeys(key_size)
        print(f"FileHandler initialized with new RSA keys (size: {key_size} bits).")

    def encryptFile(self, in_dir) -> bytes:
        """Encrypt a file in the specified directory and return the encrypted data."""
        encrypted_data = []
        try:
            for filename in os.listdir(in_dir):
                input_path = os.path.join(in_dir, filename)
                if os.path.isfile(input_path):
                    with open(input_path, 'rb') as f_in:
                        while True:
                            chunk = f_in.read(self.chunk_size)
                            if not chunk:
                                break
                            encrypted = self.rsa.encryptMessage(self.public_key, chunk.hex())
                            encrypted_data.append(encrypted)
            return '\n'.join(encrypted_data).encode()  # Return as bytes
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            return None

    def decryptFile(self, out_dir) -> bytes:
        """Decrypt data and save it to the specified directory."""
        decrypted_data = bytearray()
        try:
            for filename in os.listdir(out_dir):
                input_path = os.path.join(out_dir, filename)
                if os.path.isfile(input_path) and filename.endswith('.enc'):
                    with open(input_path, 'r') as f_in:
                        for line in f_in:
                            decrypted = self.rsa.decryptMessage(self.private_key, line.strip())
                            decrypted_data.extend(bytes.fromhex(decrypted))
            return decrypted_data
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return None

    def saveData(self, data, directory):
        """Save the given data to a file in the specified directory."""
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
            output_path = os.path.join(directory, 'output.txt')  # Example output file name
            with open(output_path, 'wb') as f:
                f.write(data)
            print(f"Data saved to {output_path}.")
            return True
        except Exception as e:
            print(f"Save failed: {str(e)}")
            return False

    def encryptDirectory(self, directory):
        """Encrypt all files in the specified directory."""
        encrypted_files = {}
        try:
            for filename in os.listdir(directory):
                input_path = os.path.join(directory, filename)
                if os.path.isfile(input_path):
                    encrypted_data = self.encryptFile(input_path)
                    if encrypted_data is not None:
                        encrypted_files[filename] = encrypted_data
            return encrypted_files
        except Exception as e:
            print(f"Encryption of directory failed: {str(e)}")
            return None

    def decryptDirectory(self, directory):
        """Decrypt all files in the specified directory."""
        decrypted_files = {}
        try:
            for filename in os.listdir(directory):
                input_path = os.path.join(directory, filename)
                if os.path.isfile(input_path) and filename.endswith('.enc'):
                    decrypted_data = self.decryptFile(input_path)
                    if decrypted_data is not None:
                        decrypted_files[filename[:-4]] = decrypted_data  # Remove .enc
            return decrypted_files
        except Exception as e:
            print(f"Decryption of directory failed: {str(e)}")
            return None
