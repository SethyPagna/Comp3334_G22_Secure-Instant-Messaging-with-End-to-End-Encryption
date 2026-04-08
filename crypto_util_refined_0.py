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
import keyring

# --- Utility Classes ---

class HKDF_util:
    @staticmethod
    def hkdf_derive_key(salt, info, input_key_material):
        key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            info = info,
        ).derive(input_key_material)
        return key

class x25519_key:
    @staticmethod
    def x25519_private_key_generation(): 
        # Fix: This actually generates the PRIVATE key object
        return X25519PrivateKey.generate()
    
    @staticmethod
    def x25519_public_key_generation(private_key):
        # Fix: This extracts the PUBLIC key object from the private key
        return private_key.public_key()
    
    @staticmethod
    def x25519_private_key_serialization(private_key):
        return private_key.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        )

    @staticmethod
    def x25519_private_key_deserialization(private_key_bytes):
        return X25519PrivateKey.from_private_bytes(private_key_bytes)
        
    @staticmethod
    def x25519_public_key_serialization(public_key):
        return public_key.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )
    
    @staticmethod
    def x25519_public_key_deserialization(public_key_bytes):
        return X25519PublicKey.from_public_bytes(public_key_bytes)

    @staticmethod
    def x25519_public_key_exchange(user1_private_key, user2_public_bytes):
        user1_import_user2_public_key = X25519PublicKey.from_public_bytes(user2_public_bytes)
        user1_shared_key_bytes = user1_private_key.exchange(user1_import_user2_public_key)
        return user1_shared_key_bytes

class ed25519_key:
    @staticmethod
    def ed25519_private_key_generation():
        return ed25519.Ed25519PrivateKey.generate()
    
    @staticmethod
    def ed25519_public_key_generation(private_key):
        return private_key.public_key()
    
    @staticmethod
    def ed25519_private_key_signature(private_key, message):
        return private_key.sign(message)
    
    @staticmethod
    def ed25519_serialization(public_key):
        return public_key.public_bytes_raw()
    
    @staticmethod
    def ed25519_deserialization(public_key_bytes):
        return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    
    @staticmethod
    def ed25519_signature_verification(public_key, signature, message):
        public_key.verify(signature, message)

# --- Protocol Logic ---

class X3DH:
    @staticmethod
    def x3DH_derive_key(dh1, dh2, dh3, dh4):
        return HKDF_util.hkdf_derive_key(b"\x00"*32, b'X3DH_session_key', dh1+dh2+dh3+dh4)
    
    @staticmethod
    def x3DH_sending_session_key(sender_identify_key, sender_ephemeral_key, receiver_identify_key_bytes, receiver_signed_pre_key_bytes, receiver_one_time_pre_key_bytes):
        dh1 = x25519_key.x25519_public_key_exchange(sender_identify_key, receiver_signed_pre_key_bytes)
        dh2 = x25519_key.x25519_public_key_exchange(sender_ephemeral_key, receiver_identify_key_bytes)
        dh3 = x25519_key.x25519_public_key_exchange(sender_ephemeral_key, receiver_signed_pre_key_bytes)
        dh4 = x25519_key.x25519_public_key_exchange(sender_ephemeral_key, receiver_one_time_pre_key_bytes)
        return X3DH.x3DH_derive_key(dh1, dh2, dh3, dh4)
    
    @staticmethod
    def x3DH_receiving_session_key(receiver_identify_key, receiver_signed_pre_key, receiver_one_time_pre_key, sender_identify_key_bytes, sender_ephemeral_key_bytes):
        dh1 = x25519_key.x25519_public_key_exchange(receiver_signed_pre_key, sender_identify_key_bytes)
        dh2 = x25519_key.x25519_public_key_exchange(receiver_identify_key, sender_ephemeral_key_bytes)
        dh3 = x25519_key.x25519_public_key_exchange(receiver_signed_pre_key, sender_ephemeral_key_bytes)
        dh4 = x25519_key.x25519_public_key_exchange(receiver_one_time_pre_key, sender_ephemeral_key_bytes)
        return X3DH.x3DH_derive_key(dh1, dh2, dh3, dh4)

class ADBuilder:
    @staticmethod
    def build_ad(session_id: str, sequence_number: int, fingerprint: str) -> bytes:
        s_id_bytes = session_id.encode('utf-8')
        seq_bytes = struct.pack('>Q', sequence_number)
        fp_bytes = fingerprint.encode('utf-8')
        return s_id_bytes + b"|" + seq_bytes + b"|" + fp_bytes

class SecureSession:
    def __init__(self, shared_key: bytes):
        self.session_id = uuid.uuid4().hex[:8]
        self.key = shared_key
        self.sequence_number = 0
        self.fingerprint = hashlib.sha256(shared_key).hexdigest()[:16]

    def encrypt_message(self, plaintext: bytes):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        ad = ADBuilder.build_ad(self.session_id, self.sequence_number, self.fingerprint)
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(self.key)
        ciphertext = chacha.encrypt(nonce, plaintext, ad)
        self.sequence_number += 1
        return base64.b64encode(nonce + ciphertext), base64.b64encode(ad)

    def decrypt_message(self, b64_encrypted_blob: bytes, b64_received_ad: bytes):
        encrypted_blob = base64.b64decode(b64_encrypted_blob)
        received_ad = base64.b64decode(b64_received_ad)
        
        nonce = encrypted_blob[:12]
        ciphertext_with_tag = encrypted_blob[12:]
        
        chacha = ChaCha20Poly1305(self.key)
        plaintext = chacha.decrypt(nonce, ciphertext_with_tag, received_ad)
        
        parts = received_ad.split(b"|")
        received_seq = struct.unpack('>Q', parts[1])[0]
        
        if received_seq < self.sequence_number:
            raise Exception("Replay Attack Detected")
        
        self.sequence_number = received_seq + 1
        return plaintext

class CryptoHandler:
    def __init__(self, user_id):
        self.user_id = user_id
        self.service_name = "X9jL2pW8mN4kR7vQ1sT5bY3zH6gD0fC9jK2lM8nP4qR7sT5vW1"
        
        stored_key = keyring.get_password(self.service_name, f"{user_id}_identity_pri")

        if stored_key:
            # --- DESERIALIZATION ---
            private_key_bytes = base64.b64decode(stored_key)
            self.ik_pri = x25519_key.x25519_private_key_deserialization(private_key_bytes)
        else:
            # --- GENERATION & SERIALIZATION ---
            self.ik_pri = X25519PrivateKey.generate()
            # Serialize to raw bytes for storage
            private_key_bytes = x25519_key.x25519_private_key_serialization(self.ik_pri)
            b64_key = base64.b64encode(private_key_bytes).decode('utf-8')
            keyring.set_password(self.service_name, f"{user_id}_identity_pri", b64_key)

        self.ik_pub = x25519_key.x25519_public_key_generation(self.ik_pri)
        self.sig_key_pri = ed25519_key.ed25519_private_key_generation()
        self.sig_key_pub = ed25519_key.ed25519_public_key_generation(self.sig_key_pri)
        self.spk_pri = x25519_key.x25519_private_key_generation()
        self.spk_pub = x25519_key.x25519_public_key_generation(self.spk_pri)
        
        spk_bytes = x25519_key.x25519_public_key_serialization(self.spk_pub)
        self.spk_signature = ed25519_key.ed25519_private_key_signature(self.sig_key_pri, spk_bytes)

    def get_bundle(self):
        return {
            "ik": x25519_key.x25519_public_key_serialization(self.ik_pub),
            "sig_key": ed25519_key.ed25519_serialization(self.sig_key_pub),
            "spk": x25519_key.x25519_public_key_serialization(self.spk_pub),
            "spk_sig": self.spk_signature
        }

    def initiate_session(self, peer_bundle, peer_otpk_bytes):
        peer_sig_pub = ed25519_key.ed25519_deserialization(peer_bundle['sig_key'])
        ed25519_key.ed25519_signature_verification(peer_sig_pub, peer_bundle['spk_sig'], peer_bundle['spk'])

        ek_pri = x25519_key.x25519_private_key_generation()
        ek_pub_bytes = x25519_key.x25519_public_key_serialization(x25519_key.x25519_public_key_generation(ek_pri))

        session_key = X3DH.x3DH_sending_session_key(
            self.ik_pri, ek_pri, peer_bundle['ik'], peer_bundle['spk'], peer_otpk_bytes
        )
        return SecureSession(session_key), ek_pub_bytes

    def receive_session(self, sender_ik_bytes, sender_ek_bytes, otpk_pri):
        session_key = X3DH.x3DH_receiving_session_key(
            self.ik_pri, self.spk_pri, otpk_pri, sender_ik_bytes, sender_ek_bytes
        )
        return SecureSession(session_key)

# running test case
if __name__ == "__main__":
    # try:
    #     # Delete the Identity Key
    #     keyring.delete_password("X9jL2pW8mN4kR7vQ1sT5bY3zH6gD0fC9jK2lM8nP4qR7sT5vW1", f"{1}_identity_pri")
    #     print(f"[*] Success: Identity key for {1} has been deleted.")
    #     keyring.delete_password("X9jL2pW8mN4kR7vQ1sT5bY3zH6gD0fC9jK2lM8nP4qR7sT5vW1", f"{2}_identity_pri")
    #     print(f"[*] Success: Identity key for {2} has been deleted.")
    # except keyring.errors.PasswordDeleteError:
    #     print("[!] Error: Key not found or already deleted.")

    alice = CryptoHandler(1)
    bob = CryptoHandler(2)

    bob_bundle = bob.get_bundle()
    bob_otpk_pri = x25519_key.x25519_private_key_generation()
    bob_otpk_pub_bytes = x25519_key.x25519_public_key_serialization(x25519_key.x25519_public_key_generation(bob_otpk_pri))

    alice_session, alice_ek_bytes = alice.initiate_session(bob_bundle, bob_otpk_pub_bytes)
    alice_ik_bytes = x25519_key.x25519_public_key_serialization(alice.ik_pub)
    
    bob_session = bob.receive_session(alice_ik_bytes, alice_ek_bytes, bob_otpk_pri)

    # Encrypt
    msg = "kkkkkk看看看看嗎？"
    c_blob, c_ad = alice_session.encrypt_message(msg)
    print(f"Encrypted: {c_blob}")

    # Decrypt
    p_text = bob_session.decrypt_message(c_blob, c_ad)
    print(f"Decrypted: {p_text.decode()}")