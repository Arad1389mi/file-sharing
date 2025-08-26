import random
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad # Still needed for padding if AESCrypto doesn't handle it internally

# Corrected import paths for RSACrypto and AESCrypto
import sys
sys.path.append("D:\\file_transfer\\src\\application\\file_cryption") # Assuming RSA.py and AES.py are in file_cryption folder
from RSA import RSACrypto # Import the RSACrypto class
from AES import AESCrypto # Import the AESCrypto class

# Keep this import for prime generation if not implementing custom prime generation
import rsa 

class HybridEncryptionSystem:
    def __init__(self, rsa_key_size=2048):
        """
        Initialize with RSA key pair generation
        Args:
            rsa_key_size: Bit length of RSA keys (default 2048)
        """
        self.rsa_crypto = RSACrypto() # Instantiate RSACrypto
        self.rsaPublicKey, self.rsaPrivateKey = self.rsa_crypto.generateKeys(rsa_key_size) # Use RSACrypto instance
        
        self.dhPrime = None  # Large prime for DH
        self.dhGenerator = None  # Generator for DH
        self.dhPrivate = None  # Our private DH key
        self.dhPublic = None  # Our public DH key
        self.sharedSecret = None  # Computed DH shared secret (will be used as AES key)
        
        # AESCrypto instance will be created once sharedSecret is established
        self.aes_crypto = None 

    def generateDHParameters(self, bits=2048):
        """
        Generate Diffie-Hellman parameters
        Args:
            bits: Bit length of DH prime (default 2048)
        """
        while True:
            p = rsa.prime.getprime(bits)
            if rsa.prime.is_prime((p-1)//2):  # Check (p-1)/2 is also prime
                self.dhPrime = p
                self.dhGenerator = 2  # Common generator
                break

    def generateDHKeys(self):
        """Generate DH private and public keys"""
        if not self.dhPrime:
            self.generateDHParameters()
        
        self.dhPrivate = random.getrandbits(256)  # 256-bit private key
        self.dhPublic = pow(self.dhGenerator, self.dhPrivate, self.dhPrime)
    
    def computeSharedSecret(self, otherPublicKey):
        """
        Compute DH shared secret from peer's public key and initialize AESCrypto.
        Args:
            otherPublicKey: Peer's DH public key
        Returns:
            Shared secret as bytes (which is the AES key)
        """
        if not self.dhPrivate:
            raise ValueError("DH private key not generated")
            
        self.sharedSecret = pow(otherPublicKey, self.dhPrivate, self.dhPrime)
        
        # Derive AES key using SHA256 from the shared secret
        hasher = SHA256.new()
        hasher.update(self.sharedSecret.to_bytes(256, 'big'))
        aes_key = hasher.digest()  # 32-byte AES key
        
        # Initialize AESCrypto with a dummy number, then set the derived key
        # The AESCrypto class expects a 'num' in its __init__ to generate a key.
        # We will override this key with our derived shared secret.
        self.aes_crypto = AESCrypto(1) # Initialize with a dummy number
        self.aes_crypto.key = aes_key # Set the actual derived key
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)

        return aes_key
    
    def encryptWithDHParams(self, message):
        """
        Encrypt a message using DH-derived symmetric key.
        This method now also performs the actual message encryption using AES.
        Args:
            message: Plaintext to encrypt (bytes)
        Returns:
            Dictionary containing:
            - iv: Initialization vector (from AESCrypto)
            - ciphertext: Encrypted message (from AESCrypto)
            - dhPublic: Our DH public key (encrypted with RSA)
            - dhPrime: DH prime (encrypted with RSA)
            - dhGenerator: DH generator (encrypted with RSA)
        """
        if not self.dhPublic:
            self.generateDHKeys()
        
        if not self.aes_crypto:
            raise ValueError("Shared secret not computed. Call computeSharedSecret first.")

        # Encrypt the actual message using AES
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # AESCrypto's aesEncrypt method expects the key as an argument, but it also uses self.key
        # We'll pass self.aes_crypto.key for clarity, though it might be redundant depending on AESCrypto's internal logic.
        ciphertext = self.aes_crypto.aesEncrypt(self.aes_crypto.key, message)
        
        # Encrypt DH params with RSA using RSACrypto instance
        encryptedPrime = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhPrime))
        encryptedGenerator = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhGenerator))
        encryptedDHPublic = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhPublic))
        
        return {
            'iv': self.aes_crypto.iv.hex(), # Send IV as hex string
            'ciphertext': ciphertext.hex(), # Send ciphertext as hex string
            'dhPublic': encryptedDHPublic,
            'dhPrime': encryptedPrime,
            'dhGenerator': encryptedGenerator
        }
    
    def decryptDHParams(self, encryptedParams):
        """
        Decrypt received DH parameters using RSA private key.
        Args:
            encryptedParams: Dictionary containing:
                - iv: Initialization vector (hex string)
                - ciphertext: Encrypted message (hex string)
                - dhPublic: Peer's DH public key (encrypted)
                - dhPrime: DH prime (encrypted)
                - dhGenerator: DH generator (encrypted)
        Returns:
            Tuple of (decrypted_message, peerPublicKey, prime, generator)
        """
        # Decrypt with RSA private key using RSACrypto instance
        prime = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhPrime']))
        generator = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhGenerator']))
        peerPublic = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhPublic']))
        
        # After decrypting DH params, compute shared secret and initialize AESCrypto
        self.computeSharedSecret(peerPublic) # This will set self.aes_crypto and its key
        
        # Decrypt the actual message using AES
        if not self.aes_crypto:
            raise ValueError("AESCrypto not initialized. Shared secret not computed.")

        received_iv = bytes.fromhex(encryptedParams['iv'])
        received_ciphertext = bytes.fromhex(encryptedParams['ciphertext'])

        # Temporarily set the IV for decryption, as AESCrypto's __init__ sets it
        # A better design for AESCrypto would be to pass IV to encrypt/decrypt methods
        original_aes_iv = self.aes_crypto.iv
        self.aes_crypto.iv = received_iv
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)

        decrypted_message = self.aes_crypto.aesDecrypt(self.aes_crypto.key, received_ciphertext)
        
        # Restore original IV if necessary (or just let it be overwritten on next use)
        self.aes_crypto.iv = original_aes_iv # Or generate a new random IV for next encryption
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)


        return (decrypted_message, peerPublic, prime, generator)


    
