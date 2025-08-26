import os
from RSA import RSACrypto

class FileHandler:
    def __init__(self):
        self.rsa = RSACrypto()
        self.chunk_size = 214  # Max bytes RSA-2048 can encrypt

    def encrypt_file(self, input_path, output_path, public_key):
        """Encrypt file with RSA public key"""
        try:
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(self.chunk_size)
                    if not chunk:
                        break
                    encrypted = self.rsa.encrypt_message(public_key, chunk.hex())
                    f_out.write(encrypted.encode() + b'\n')  # Newline separator
            return True
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            return False

    def decrypt_file(self, input_path, output_path, private_key):
        """Decrypt file with RSA private key""" 
        try:
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                for line in f_in:
                    decrypted = self.rsa.decrypt_message(private_key, line.strip().decode())
                    f_out.write(bytes.fromhex(decrypted))
            return True
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return False

    def generate_key_pair(self, key_size=2048):
        """Generate RSA key pair"""
        return self.rsa.generate_keys(key_size)

    def save_encrypted_data(self, data, file_path, public_key):
        """Save encrypted string data to file"""
        try:
            encrypted = self.rsa.encrypt_message(public_key, data)
            with open(file_path, 'w') as f:
                f.write(encrypted)
            return True
        except Exception as e:
            print(f"Save failed: {str(e)}")
            return False

    def load_encrypted_data(self, file_path, private_key):
        """Load and decrypt data from file"""
        try:
            with open(file_path, 'r') as f:
                encrypted = f.read()
            return self.rsa.decrypt_message(private_key, encrypted)
        except Exception as e:
            print(f"Load failed: {str(e)}")
            return None

    def encrypt_directory(self, dir_path, output_dir, public_key):
        """Encrypt all files in directory"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        for filename in os.listdir(dir_path):
            input_path = os.path.join(dir_path, filename)
            output_path = os.path.join(output_dir, filename + '.enc')
            self.encrypt_file(input_path, output_path, public_key)

    def decrypt_directory(self, dir_path, output_dir, private_key):
        """Decrypt all files in directory"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        for filename in os.listdir(dir_path):
            if filename.endswith('.enc'):
                input_path = os.path.join(dir_path, filename)
                output_path = os.path.join(output_dir, filename[:-4])  # Remove .enc
                self.decrypt_file(input_path, output_path, private_key)
