import random
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import sys
sys.path.append("D:\\file_transfer\\src\\crypto\\algorithms")
from RSA import RSACrypto
from AES import AESCrypto
import rsa 

class HybridEncryptionSystem:
    def __init__(self, rsa_key_size=2048):
        self.rsa_crypto = RSACrypto()
        self.rsaPublicKey, self.rsaPrivateKey = self.rsa_crypto.generateKeys(rsa_key_size)
        self.dhPrime = None
        self.dhGenerator = None
        self.dhPrivate = None
        self.dhPublic = None
        self.sharedSecret = None
        self.aes_crypto = None 

    def generateDHParameters(self, bits=2048):
        while True:
            p = rsa.prime.getprime(bits)
            if rsa.prime.is_prime((p-1)//2):
                self.dhPrime = p
                self.dhGenerator = 2
                break

    def generateDHKeys(self):
        if not self.dhPrime:
            self.generateDHParameters()
        self.dhPrivate = random.getrandbits(256)
        self.dhPublic = pow(self.dhGenerator, self.dhPrivate, self.dhPrime)
    
    def computeSharedSecret(self, otherPublicKey):
        if not self.dhPrivate:
            raise ValueError("DH private key not generated")
        self.sharedSecret = pow(otherPublicKey, self.dhPrivate, self.dhPrime)
        hasher = SHA256.new()
        hasher.update(self.sharedSecret.to_bytes(256, 'big'))
        aes_key = hasher.digest()
        self.aes_crypto = AESCrypto(1)
        self.aes_crypto.key = aes_key
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)
        return aes_key
    
    def encryptWithDHParams(self, message):
        if not self.dhPublic:
            self.generateDHKeys()
        if not self.aes_crypto:
            raise ValueError("Shared secret not computed. Call computeSharedSecret first.")
        if isinstance(message, str):
            message = message.encode('utf-8')
        ciphertext = self.aes_crypto.aesEncrypt(self.aes_crypto.key, message)
        encryptedPrime = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhPrime))
        encryptedGenerator = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhGenerator))
        encryptedDHPublic = self.rsa_crypto.encryptMessage(self.rsaPublicKey, str(self.dhPublic))
        return {
            'iv': self.aes_crypto.iv.hex(),
            'ciphertext': ciphertext.hex(),
            'dhPublic': encryptedDHPublic,
            'dhPrime': encryptedPrime,
            'dhGenerator': encryptedGenerator
        }
    
    def decryptDHParams(self, encryptedParams):
        prime = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhPrime']))
        generator = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhGenerator']))
        peerPublic = int(self.rsa_crypto.decryptMessage(self.rsaPrivateKey, encryptedParams['dhPublic']))
        self.computeSharedSecret(peerPublic)
        if not self.aes_crypto:
            raise ValueError("AESCrypto not initialized. Shared secret not computed.")
        received_iv = bytes.fromhex(encryptedParams['iv'])
        received_ciphertext = bytes.fromhex(encryptedParams['ciphertext'])
        original_aes_iv = self.aes_crypto.iv
        self.aes_crypto.iv = received_iv
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)
        decrypted_message = self.aes_crypto.aesDecrypt(self.aes_crypto.key, received_ciphertext)
        self.aes_crypto.iv = original_aes_iv
        self.aes_crypto.cipher = Cipher(algorithms.AES(self.aes_crypto.key), modes.CBC(self.aes_crypto.iv), backend=self.aes_crypto.backend)
        return (decrypted_message, peerPublic, prime, generator)
