import requests
import threading
import time
import logging
from datetime import datetime
from typing import Optional, Dict, List
from local_store import LocalStore

# Import Member 1's crypto utils (adjust import based on actual structure)
# from crypto_utils import CryptoUtils, X3DH, ChaCha20Poly1305, HKDF

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class API:
    """HTTP wrapper for all server endpoints"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.access_token = None
    
    def set_token(self, token: str):
        self.access_token = token
        self.session.headers.update({'Authorization': f'Bearer {token}'})
    
    def _request(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    
    def register(self, user_id: str, password: str, identity_key: str, 
                 signed_prekey: str, one_time_prekeys: List[str]):
        return self._request('POST', '/register', json={
            'user_id': user_id,
            'password': password,
            'identity_key': identity_key,
            'signed_prekey': signed_prekey,
            'one_time_prekeys': one_time_prekeys
        })
    
    def login(self, user_id: str, password: str, totp_code: str):
        data = self._request('POST', '/login', json={
            'user_id': user_id,
            'password': password,
            'totp_code': totp_code
        })
        self.set_token(data['access_token'])
        return data
    
    def logout(self):
        self._request('POST', '/logout')
        self.access_token = None
        self.session.headers.pop('Authorization', None)
    
    def get_public_key(self, user_id: str):
        return self._request('GET', f'/keys/{user_id}')
    
    def send_friend_request(self, target_id: str):
        return self._request('POST', '/friends/request', json={'target_id': target_id})
    
    def accept_friend(self, requester_id: str):
        return self._request('POST', '/friends/accept', json={'requester_id': requester_id})
    
    def decline_friend(self, requester_id: str):
        return self._request('POST', '/friends/decline', json={'requester_id': requester_id})
    
    def list_friends(self):
        return self._request('GET', '/friends')
    
    def send_message(self, recipient_id: str, ciphertext: str, message_id: str, ttl: int = None):
        return self._request('POST', '/messages', json={
            'recipient_id': recipient_id,
            'ciphertext': ciphertext,
            'message_id': message_id,
            'ttl': ttl
        })
    
    def poll_messages(self):
        return self._request('GET', '/messages/poll')
    
    def ack_message(self, message_id: str):
        return self._request('POST', f'/messages/{message_id}/ack')
    
    def poll_delivery_receipts(self):
        return self._request('GET', '/delivery/receipts')
    
    def block_user(self, user_id: str):
        return self._request('POST', '/block', json={'user_id': user_id})
    
    def unblock_user(self, user_id: str):
        return self._request('POST', '/unblock', json={'user_id': user_id})


class CryptoEngine:
    """Session management and crypto wrappers"""
    
    def __init__(self, store: LocalStore):
        self.store = store
        self.sessions: Dict[str, dict] = {}  # contact_id -> session dict
        # TODO: Initialize Member 1's crypto utils
    
    def init_from_identity(self):
        """Load identity from store and initialize crypto"""
        identity = self.store.get_identity()
        if not identity:
            raise ValueError("No identity found")
        
        # TODO: Use crypto_utils to load keypair
        # self.identity_private = CryptoUtils.load_private_key(identity['identity_private_key'])
        # self.identity_public = CryptoUtils.load_public_key(identity['identity_public_key'])
        # self.signed_prekey = identity['signed_prekey']
        
        logger.info(f"Initialized crypto engine for user {identity.get('user_id')}")
    
    def create_session(self, contact_id: str, their_identity_key: str, 
                       their_signed_prekey: str, one_time_prekey: str = None):
        """Run X3DH to establish a shared session"""
        # TODO: Implement X3DH using crypto_utils
        # Returns session_id and session keys
        session_id = f"session_{contact_id}_{int(time.time())}"
        
        # Mock session keys (replace with actual X3DH output)
        send_chain_key = "mock_send_key"
        recv_chain_key = "mock_recv_key"
        send_header_key = "mock_header_key"
        recv_header_key = "mock_header_key"
        
        # Store session
        self.store.save_session(
            contact_id, session_id,
            send_chain_key, recv_chain_key,
            send_header_key, recv_header_key
        )
        
        self.sessions[contact_id] = {
            'session_id': session_id,
            'send_chain_key': send_chain_key,
            'recv_chain_key': recv_chain_key
        }
        
        return session_id
    
    def encrypt_message(self, contact_id: str, plaintext: str) -> tuple:
        """Encrypt message using existing session"""
        session = self.sessions.get(contact_id)
        if not session:
            raise ValueError(f"No session for {contact_id}")
        
        # TODO: Use ChaCha20-Poly1305 with session keys
        # Include message ID and associated data
        message_id = f"{contact_id}_{int(time.time())}"
        associated_data = self._build_ad(contact_id, message_id)
        
        # Mock encryption
        ciphertext = f"encrypted_{plaintext}"
        nonce = "mock_nonce"
        
        return ciphertext, nonce, message_id
    
    def decrypt_message(self, contact_id: str, ciphertext: str, nonce: str) -> str:
        """Decrypt message using existing session"""
        session = self.sessions.get(contact_id)
        if not session:
            raise ValueError(f"No session for {contact_id}")
        
        # TODO: Use ChaCha20-Poly1305 to decrypt
        # Mock decryption
        if ciphertext.startswith("encrypted_"):
            return ciphertext[10:]
        return ciphertext
    
    def _build_ad(self, contact_id: str, message_id: str) -> bytes:
        """Build authenticated associated data"""
        # TODO: Include contact_id, message_id, and timestamp
        return f"{contact_id}:{message_id}".encode()
    
    def verify_key_change(self, contact_id: str, new_identity_key: str) -> bool:
        """Check if key fingerprint changed unexpectedly"""
        trusted = self.store.get_trusted_key(contact_id)
        if not trusted:
            # First time seeing this key
            self.store.save_trusted_key(contact_id, new_identity_key)
            return True
        
        # TODO: Generate fingerprint of new_key and compare
        # If different, trigger key-change detection
        if trusted['identity_key'] != new_identity_key:
            logger.warning(f"Key change detected for {contact_id}!")
            return False
        return True


class MessagePoller(threading.Thread):
    """Background thread to poll for new messages"""
    
    def __init__(self, api: API, crypto: CryptoEngine, store: LocalStore):
        super().__init__(daemon=True)
        self.api = api
        self.crypto = crypto
        self.store = store
        self.running = True
    
    def run(self):
        while self.running:
            try:
                messages = self.api.poll_messages()
                for msg in messages:
                    self._process_message(msg)
                time.sleep(3)
            except Exception as e:
                logger.error(f"Polling error: {e}")
                time.sleep(5)
    
    def _process_message(self, msg):
        """Decrypt and store incoming message"""
        # Replay check
        if self.store.is_nonce_seen(msg['message_id']):
            logger.warning(f"Replay attack detected: {msg['message_id']}")
            return
        
        # Decrypt
        try:
            plaintext = self.crypto.decrypt_message(
                msg['sender_id'], 
                msg['ciphertext'], 
                msg['nonce']
            )
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return
        
        # Store message
        self.store.save_message(
            msg['message_id'],
            msg['sender_id'],  # conversation_id
            msg['sender_id'],
            msg['recipient_id'],
            plaintext,
            'received',
            msg.get('ttl', 86400)
        )
        
        # Update conversation
        self.store.update_conversation(msg['sender_id'], plaintext, is_from_contact=True)
        
        # ACK to server
        self.api.ack_message(msg['message_id'])


class ReceiptPoller(threading.Thread):
    """Background thread to poll for delivery receipts"""
    
    def __init__(self, api: API, store: LocalStore):
        super().__init__(daemon=True)
        self.api = api
        self.store = store
        self.running = True
    
    def run(self):
        while self.running:
            try:
                receipts = self.api.poll_delivery_receipts()
                for receipt in receipts:
                    self.store.update_message_status(receipt['message_id'], 'delivered')
                time.sleep(3)
            except Exception as e:
                logger.error(f"Receipt polling error: {e}")
                time.sleep(5)


class ExpiryWorker(threading.Thread):
    """Background thread to delete expired messages"""
    
    def __init__(self, store: LocalStore):
        super().__init__(daemon=True)
        self.store = store
        self.running = True
    
    def run(self):
        while self.running:
            try:
                expired = self.store.get_expired_messages()
                if expired:
                    ids = [msg['id'] for msg in expired]
                    self.store.delete_messages(ids)
                    logger.info(f"Deleted {len(expired)} expired messages")
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Expiry error: {e}")
                time.sleep(60)


class ClientCore:
    """Main client orchestrator"""
    
    def __init__(self, server_url: str, db_path: str = "client.db"):
        self.store = LocalStore(db_path)
        self.api = API(server_url)
        self.crypto = CryptoEngine(self.store)
        
        # Background threads
        self.message_poller = None
        self.receipt_poller = None
        self.expiry_worker = None
    
    def login(self, user_id: str, password: str, totp_code: str):
        """Login and start background services"""
        data = self.api.login(user_id, password, totp_code)
        self.crypto.init_from_identity()
        
        # Start background threads
        self.message_poller = MessagePoller(self.api, self.crypto, self.store)
        self.receipt_poller = ReceiptPoller(self.api, self.store)
        self.expiry_worker = ExpiryWorker(self.store)
        
        self.message_poller.start()
        self.receipt_poller.start()
        self.expiry_worker.start()
        
        return data
    
    def logout(self):
        """Stop background services and logout"""
        self.message_poller.running = False
        self.receipt_poller.running = False
        self.expiry_worker.running = False
        self.api.logout()
    
    def send_message(self, contact_id: str, plaintext: str, ttl: int = None):
        """Send encrypted message to contact"""
        # Ensure session exists
        if contact_id not in self.crypto.sessions:
            # Fetch contact's public keys and establish session
            key_data = self.api.get_public_key(contact_id)
            self.crypto.create_session(
                contact_id,
                key_data['identity_key'],
                key_data['signed_prekey'],
                key_data.get('one_time_prekey')
            )
        
        # Encrypt
        ciphertext, nonce, message_id = self.crypto.encrypt_message(contact_id, plaintext)
        
        # Store locally
        self.store.save_message(
            message_id, contact_id, 
            self.store.get_identity()['user_id'], contact_id,
            plaintext, 'sent', ttl or 86400
        )
        
        # Send to server
        self.api.send_message(contact_id, ciphertext, message_id, ttl)
        
        return message_id
    
    def get_conversations(self):
        """Get list of conversations with unread counts"""
        with self.store.get_connection() as conn:
            return conn.execute("""
                SELECT * FROM conversations ORDER BY last_message_time DESC
            """).fetchall()
    
    def get_messages(self, contact_id: str, limit: int = 50):
        """Get messages for a contact"""
        with self.store.get_connection() as conn:
            return conn.execute("""
                SELECT * FROM messages WHERE conversation_id = ?
                ORDER BY created_at DESC LIMIT ?
            """, (contact_id, limit)).fetchall()
    
    def mark_conversation_read(self, contact_id: str):
        """Mark all messages from contact as read"""
        self.store.mark_conversation_read(contact_id)