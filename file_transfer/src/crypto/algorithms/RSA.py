import rsa


class RSACrypto:
    def __init__(self):
        pass
        
        
        


    def generateKeys(self, bits=2048):
        """Generate RSA public/private key pair (default: 2048 bits)."""
        (publicKey, privateKey) = rsa.newkeys(bits)
        return (publicKey, privateKey)

    def encryptMessage(self, publicKey, message):
        """Encrypt a message using RSA public key."""
        encodedData = message.encode('utf-8')  # Convert to bytes
        encData = rsa.encrypt(encodedData, publicKey)
        return encData.hex()  # Return as hex string for readability

    def decryptMessage(self, privateKey, encryptedData):
        """Decrypt ciphertext (hex string) using RSA private key."""
        encData = bytes.fromhex(encryptedData)  # Convert hex back to bytes
        decData = rsa.decrypt(encData, privateKey)
        return encData.decode('utf-8')# Convert to string

if __name__ == "__main__":
    r = RSACrypto()
        # Example Usage
    (publicKey, privateKey) = r.generateKeys(bits=2048)

    message = "Hello, secure world!"
    print(f"Original message: {message}")

    ciphertextHex = r.encryptMessage(publicKey, message)
    print(f"Encrypted (hex): {ciphertextHex}")

    decrypted = r.decryptMessage(privateKey, ciphertextHex)
    print(f"Decrypted message: {decrypted}")
