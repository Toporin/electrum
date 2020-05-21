from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import Cipher

from os import urandom
from hashlib import sha1, sha256
import hmac

class SecureChannel:

    def __init__(self):
        
        self.initialized_secure_channel= False
        self.sc_privkey= None
        self.sc_pubkey= None
        self.sc_peer_pubkey= None
        self.sc_IV= None
        self.sc_IVcounter= None
        self.shared_key = None
        self.derived_key = None
        self.mac_key = None
        
        self.sc_privkey = ec.generate_private_key( ec.SECP256K1(), default_backend() )
        self.sc_pubkey = self.sc_privkey.public_key()
        self.sc_pubkey_serialized=  self.sc_pubkey.public_bytes(encoding= Encoding.X962, format= PublicFormat.UncompressedPoint)
        #self.sc_pubkey_serialized= self.sc_pubkey.public_numbers().encode_point() #deprecated
        # x= self.sc_pubkey.public_numbers().x
        # y= self.sc_pubkey.public_numbers().y
        # self.sc_pubkey_serialized=  b'\x04' + x.to_bytes(32, byteorder='big') + y.to_bytes(32, byteorder='big')
    
    def initiate_secure_channel(self, peer_pubkey_bytes):
        print("In initiate_secure_channel()")
        
        self.sc_peer_pubkey= ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), peer_pubkey_bytes)
        self.sc_IVcounter= 1
        self.shared_key = self.sc_privkey.exchange(ec.ECDH(), self.sc_peer_pubkey)
        
        print("Shared key:"+ self.shared_key.hex()) #debug
        
        mac = hmac.new(self.shared_key, "sc_key".encode('utf-8'), sha1)
        self.derived_key= mac.digest()[:16]
        mac = hmac.new(self.shared_key, "sc_mac".encode('utf-8'), sha1)
        self.mac_key= mac.digest()
        
        # tmp_key= sha256(self.shared_key).digest()
        # self.derived_key = tmp_key[:16]
        # tmp_key= sha256(tmp_key).digest()
        # self.mac_key= tmp_key[:20]
        
        print("Derived_key key:"+ self.derived_key.hex()) #debug
        self.initialized_secure_channel= True
        
    
    def encrypt_secure_channel(self, data_bytes):
        
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        key= self.derived_key
        iv= urandom(12)+(self.sc_IVcounter).to_bytes(4, byteorder='big')
        encryptor= Cipher( AES(key), CBC(iv), backend=default_backend()).encryptor()
        
        ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
        self.sc_IVcounter+=2
        
        data_to_mac= iv + len(ciphertext).to_bytes(2, byteorder='big') + ciphertext
        mac = hmac.new(self.mac_key, data_to_mac, sha1).digest()
        
        return (iv, ciphertext, mac)
    
    
    def decrypt_secure_channel(self, iv, ciphertext):
    
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError('Secure channel is not initialized')
        
        key= self.derived_key
        decryptor = Cipher( AES(key), CBC(iv), backend=default_backend() ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()
        
        
        
            
class UninitializedSecureChannelError(Exception):    
    """Raised when the secure channel is not initialized"""
    pass   