from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os

class AESCrypto:
    
    def __init__(self, num):
        self.backend = default_backend()
        self.iv = os.urandom(16)
        self.number = num
        self.key = self.aesKeyGenerate()
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        
    def aesKeyGenerate(self, key_size=256):
        """
        Convert your number to a valid AES key
        
        Args:
            your_number: The number you want to use (int or string representation)
            key_size: AES key size in bits (128, 192, or 256)
            
        Returns:
            bytes: Valid AES key
        """
        # Convert number to bytes
        if isinstance(self.number, int):
            numBytes = self.number.to_bytes((self.number.bit_length() + 7) // 8, 'big')
        else:
            numBytes = str(self.number).encode()
        
        # Hash the bytes to get proper key length
        keyBytes = key_size // 8
        key = hashlib.sha256(numBytes).digest()[:keyBytes]
        return key
    
    def aesEncrypt(self, key, data):
        """Encrypt with AES-CBC"""
         # Simple IV for demonstration - in real use, generate random IV
        padder = padding.PKCS7(128).padder()
        
        encryptor = self.cipher.encryptor()
        paddedEncData = padder.update(data) + padder.finalize()
        cipherData = encryptor.update(paddedEncData) + encryptor.finalize()
        
        return cipherData
    
    def aesDecrypt(self, key, cipherData):
        """Decrypt with AES-CBC"""
        unpadder = padding.PKCS7(128).unpadder()
        
        decryptor = self.cipher.decryptor()
        paddeddecData = decryptor.update(cipherData) + decryptor.finalize()
        decData = unpadder.update(paddeddecData) + unpadder.finalize()
        
        return decData

# Example usage
if __name__ == "__main__":
    aes = AESCrypto(123456789)
    
    # 1. Choose your custom number
      # Can be any integer or string
    
    # 2. Convert to AES key
    key = aes.aesKeyGenerate(256)
    print(f"Generated AES key: {key}")
    
    # 3. Encrypt a message
    message = b"Secret message to encrypt"
    ciphertext = aes.aesEncrypt(key, message)
    print(f"Encrypted: {ciphertext}")
    
    # 4. Decrypt the message
    decrypted = aes.aesDecrypt(key, ciphertext)
    print(f"Decrypted: {decrypted.decode()}")
