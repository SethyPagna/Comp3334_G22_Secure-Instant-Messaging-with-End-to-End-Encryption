from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.serialization as serialization
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hmac, hashlib, time, struct, base64
import uuid

class HKDF_util:
    def hkdf_derive_key(salt, info, input_key_material):
        key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            info = info,
        ).derive(input_key_material)
        return key

class x25519_key:
    def __init__(self,salt,info):
        self.salt = salt
        self.info = info
    
    def x25519_public_key_generation():
        private_key = X25519PrivateKey.generate()
        return private_key
    
    def x25519_private_key_generation(private_key):
        public_key = private_key.public_key()
        return public_key
    
    def x25519_public_key_serialization(public_key):
        public_key_bytes = public_key.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )
        return public_key_bytes
    
    def x25519_public_key_deserialization(public_key_bytes):
        public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
        return public_key

    def x25519_public_key_exchange(user1_private_key,user2_public_bytes):
        user1_import_user2_public_key = X25519PublicKey.from_publc_bytes(user2_public_bytes)
        user1_shared_key_bytes = user1_private_key.exchange(user1_import_user2_public_key)
        return user1_shared_key_bytes
    
    def x25519_derived_key(salt, info, user_shared_key_bytes):
        key = HKDF_util.hkdf_derive_key(salt, info,     user_shared_key_bytes)
        return key
    
class ed25519_key:
    def ed25519_private_key_generation():
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key
    
    def ed25519_public_key_generation(private_key):
        public_key = private_key.public_key()
        return public_key
    
    def ed25519_private_key_signature(private_key,message):
        signature = private_key.sign(message)
        return signature
    
    def ed25519_serialization(public_key):
        public_bytes = public_key.public_bytes_raw()
        return public_bytes
    
    def ed25519_deserialization(public_key_bytes):
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        return public_key
    
    def ed25519_signature_verification(public_key,signature,message):
        try:
            public_key.verify(signature,message)
        except:
            print("alert")
            # idk this part may need to response to other component
        
class X3DH:
    def x3DH_private_key_generation():
        private_key = x25519_key.x25519_public_key_generation()
        return private_key
    
    def x3DH_public_key_generation(private_key):
        public_key = x25519_key.x25519_private_key_generation(private_key)
        return public_key
    
    def x3DH_public_key_serialization(public_key):
        public_key_bytes = x25519_key.x25519_public_key_serialization(public_key)
        return public_key_bytes
    
    def x3DH_derive_key(dh1,dh2,dh3,dh4):
        """X3DH Key Derivation Function (HKDF)"""
        hkdf = HKDF_util.hkdf_derive_key(b"\x00"*32, b'X3DH_session_key',dh1+dh2+dh3+dh4)
        return hkdf
    
    def x3DH_sending_session_key(sender_identify_key,sender_ephemeral_key,receiver_identify_key_bytes,receiver_signed_pre_key_bytes,receiver_one_time_pre_key_bytes):
        dh1 = sender_identify_key.x25519_public_key_exchange(sender_identify_key,x25519_key.x25519_public_key_deserialization(receiver_signed_pre_key_bytes))
        dh2 = sender_ephemeral_key.x25519_public_key_exchange(sender_ephemeral_key,x25519_key.x25519_public_key_deserialization(receiver_identify_key_bytes))
        dh3 = sender_ephemeral_key.x25519_public_key_exchange(sender_ephemeral_key,x25519_key.x25519_public_key_deserialization(receiver_signed_pre_key_bytes))
        dh4 = sender_ephemeral_key.x25519_public_key_exchange(sender_ephemeral_key,x25519_key.x25519_public_key_deserialization(receiver_one_time_pre_key_bytes))
        session_key = X3DH.x3DH_derive_key(dh1,dh2,dh3,dh4)
        return session_key
    
    def x3DH_receiving_session_key(receiver_identify_key,receiver_signed_pre_key,receiver_one_time_pre_key_bytes,sender_identify_key_bytes,sender_ephemeral_key_bytes):
        dh1 = receiver_signed_pre_key.x25519_public_key_exchange(receiver_signed_pre_key,x25519_key.x25519_public_key_deserialization(sender_identify_key_bytes))
        dh2 = receiver_identify_key.x25519_public_key_exchange(receiver_identify_key,x25519_key.x25519_public_key_deserialization(sender_ephemeral_key_bytes))
        dh3 = receiver_signed_pre_key.x25519_public_key_exchange(receiver_signed_pre_key,x25519_key.x25519_public_key_deserialization(sender_ephemeral_key_bytes))
        dh4 = receiver_one_time_pre_key_bytes.x25519_public_key_exchange(receiver_one_time_pre_key_bytes,x25519_key.x25519_public_key_deserialization(sender_ephemeral_key_bytes))
        session_key = X3DH.x3DH_derive_key(dh1,dh2,dh3,dh4)
        return session_key

class ChaCha20poly1305_cipher:
    def encrypt_message(key, plaintext, associated_data=None):
        """
        Encrypts data using ChaCha20-Poly1305.

        :param bytes key: A 32-byte (256-bit) secret key.
        :param bytes plaintext: The data to encrypt.
        :param bytes associated_data: Optional associated data (e.g., headers) to authenticate but not encrypt.
        :return bytes: The combined ciphertext and 16-byte authentication tag.
        """
        # Nonce must be 12 bytes long and unique for every encryption with the same key
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        
        # Encrypt and authenticate
        if associated_data is not None:
            ciphertext_with_tag = chacha.encrypt(nonce, plaintext, associated_data)
        else:
            # If no associated data, pass None
            ciphertext_with_tag = chacha.encrypt(nonce, plaintext, None)

        # Return the nonce along with the ciphertext so it can be used for decryption
        return nonce + ciphertext_with_tag

    def decrypt_message(key, encrypted_message, associated_data=None):
        """
        Decrypts data using ChaCha20-Poly1305 and verifies authenticity.

        :param bytes key: The same 32-byte secret key used for encryption.
        :param bytes encrypted_message: The nonce + combined ciphertext and tag.
        :param bytes associated_data: The same associated data used during encryption.
        :return bytes: The original plaintext if authentication succeeds.
        :raises cryptography.exceptions.InvalidTag: If the data is tampered with.
        """
        # Extract the nonce (first 12 bytes)
        nonce = encrypted_message[:12]
        # Extract the ciphertext with tag
        ciphertext_with_tag = encrypted_message[12:]
        
        chacha = ChaCha20Poly1305(key)

        # Decrypt and verify authenticity
        if associated_data is not None:
            plaintext = chacha.decrypt(nonce, ciphertext_with_tag, associated_data)
        else:
            # If no associated data, pass None
            plaintext = chacha.decrypt(nonce, ciphertext_with_tag, None)

        return plaintext

    # --- Example Usage ---
    # if __name__ == '__main__':
    #     # 1. Generate a secure, random 32-byte key (store this securely!)
    #     encryption_key = os.urandom(32)

    #     # 2. Define plaintext and optional associated data
    #     original_message = b"Hello, this is a secret message!"
    #     # Associated data (AAD) is authenticated but not encrypted (e.g., packet headers)
    #     aad = b"v1.0-packet-header" 

    #     # 3. Encrypt the message with AAD
    #     full_encrypted_data = encrypt_message(encryption_key, original_message, aad)
    #     print(f"Encrypted data (Nonce + Ciphertext + Tag): {full_encrypted_data.hex()}")

    #     # 4. Decrypt the message with the *same* AAD
    #     decrypted_message = decrypt_message(encryption_key, full_encrypted_data, aad)
    #     print(f"Decrypted message: {decrypted_message.decode('utf-8')}")

    #     # 5. Example of failed decryption due to data tampering
    #     try:
    #         tampered_data = full_encrypted_data[:-1] + b'!' # Tamper with the last byte of the tag
    #         decrypt_message(encryption_key, tampered_data, aad)
    #     except Exception as e:
    #         print(f"\nCaught expected error after tampering: {e}")

class TOTP:
    def get_totp(secret: str, time_step: int = 30, digits: int = 6) -> str:
        """Generates a RFC 6238 compliant TOTP code."""
        # Decode base32 secret
        key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
        # Calculate counter based on time
        counter = int(time.time() // time_step)
        msg = struct.pack('>Q', counter)
        
        # HMAC-SHA1 to generate hash
        h = hmac.new(key, msg, hashlib.sha1).digest()
        
        # Dynamic truncation (RFC 4226)
        offset = h[-1] & 0x0F
        code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
        
        # Format to desired digits
        return str(code % (10 ** digits)).zfill(digits)
    
class SHA256_util:
    def format_sha256_fingerprint(data_string):
        """
        Generates an SHA-256 hash from a string and formats it as a 
        colon-separated hexadecimal fingerprint.

        Args:
            data_string (str): The input string to hash.

        Returns:
            str: The formatted SHA-256 fingerprint string.
        """
        # 1. Encode the string to bytes (hash functions work on bytes)
        data_bytes = data_string.encode('utf-8')
        
        # 2. Generate the SHA-256 hash object
        hash_object = hashlib.sha256(data_bytes)
        
        # 3. Get the raw hash bytes (digest())
        hash_bytes = hash_object.digest()
        
        # 4. Format each byte into a two-character hex string, joined by colons
        # The '02x' format specifier ensures each byte is zero-padded to two characters
        fingerprint = ":".join([f"{byte:02x}" for byte in hash_bytes])
        
        return fingerprint
    
class Relay_detection_message:
    def generate_replay_safe_id(sender_id, message_body):
        """
        Generates a unique message ID for replay detection.
        
        Args:
            sender_id (str): Unique identifier of the sender.
            message_body (str): The content of the message.
            
        Returns:
            str: A unique hash serving as the message ID.
        """
        # 1. Use a high-precision timestamp to ensure chronological uniqueness
        timestamp = str(time.time_ns())
        
        # 2. Use a UUID (nonce) to prevent collisions within the same nanosecond
        nonce = uuid.uuid4().hex
        
        # 3. Combine components and hash them to create a compact, unique ID
        unique_string = f"{sender_id}:{timestamp}:{nonce}:{message_body}"
        message_id = hashlib.sha256(unique_string.encode('utf-8')).hexdigest()
        
        return message_id
    
class ADBuilder:
    @staticmethod
    def build_ad(session_id: str, sequence_number: int, fingerprint: str) -> bytes:
        """
        R7/R8/R9: Builds the Associated Data block.
        Structure: SessionID (UUID) | Sequence (8 bytes) | Fingerprint (Hash)
        """
        # Ensure session_id is in bytes
        s_id_bytes = session_id.encode('utf-8')
        # Sequence number prevents Replay (R9)
        seq_bytes = struct.pack('>Q', sequence_number)
        # Fingerprint ensures device/key binding (R5)
        fp_bytes = fingerprint.encode('utf-8')
        
        return s_id_bytes + b"|" + seq_bytes + b"|" + fp_bytes

class SecureSession:
    def __init__(self, sender_id: str, shared_key: bytes):
        self.session_id = uuid.uuid4().hex  # R7 Session Setup
        self.key = shared_key
        self.sequence_number = 0  # R9 Replay prevention counter
        self.sender_id = sender_id
        # Generate a fingerprint for this session (R5)
        self.fingerprint = SHA256_util.format_sha256_fingerprint(sender_id + self.session_id)

    def seal_message(self, plaintext: bytes) -> bytes:
        """R8: AEAD Encryption with built AD"""
        # 1. Build the AD
        ad = ADBuilder.build_ad(self.session_id, self.sequence_number, self.fingerprint)
        
        # 2. Encrypt using your ChaCha20 class
        encrypted_blob = ChaCha20poly1305_cipher.encrypt_message(self.key, plaintext, ad)
        
        # 3. Increment sequence for next message (Replay Protection)
        self.sequence_number += 1
        
        return encrypted_blob, ad

    def unseal_message(self, encrypted_blob: bytes, received_ad: bytes):
        """R8: AEAD Decryption and R9: Replay Validation"""
        # 1. Decrypt (This fails if AD was tampered with)
        plaintext = ChaCha20poly1305_cipher.decrypt_message(self.key, encrypted_blob, received_ad)
        
        # 2. Extract and verify sequence number (R9)
        # We assume the AD structure is [32 chars]| [8 bytes] | [rest]
        parts = received_ad.split(b"|")
        received_seq = struct.unpack('>Q', parts[1])[0]
        
        if received_seq < self.sequence_number:
            raise Exception("Replay Attack Detected: Old sequence number.")
        
        self.sequence_number = received_seq + 1
        return plaintext
