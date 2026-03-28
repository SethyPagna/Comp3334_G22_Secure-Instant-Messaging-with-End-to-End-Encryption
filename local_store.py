import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime
import os

class LocalStore:
    def __init__(self, db_path="client.db"):
        self.db_path = db_path
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def init_db(self):
        with self.get_connection() as conn:
            # Identity (your own keys)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    user_id TEXT UNIQUE,
                    identity_private_key TEXT,
                    identity_public_key TEXT,
                    signed_prekey TEXT,
                    prekey_signature TEXT,
                    one_time_prekeys TEXT,  -- JSON list
                    totp_secret TEXT,
                    created_at INTEGER
                )
            """)
            
            # Sessions for each contact
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    contact_id TEXT,
                    session_id TEXT,
                    send_chain_key TEXT,
                    recv_chain_key TEXT,
                    send_header_key TEXT,
                    recv_header_key TEXT,
                    created_at INTEGER,
                    last_used INTEGER,
                    PRIMARY KEY (contact_id, session_id)
                )
            """)
            
            # Messages
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT UNIQUE,
                    conversation_id TEXT,
                    sender_id TEXT,
                    receiver_id TEXT,
                    content TEXT,
                    direction TEXT,  -- 'sent' or 'received'
                    status TEXT,     -- 'pending', 'sent', 'delivered', 'read'
                    ttl_seconds INTEGER,
                    expires_at INTEGER,
                    created_at INTEGER,
                    delivered_at INTEGER,
                    read_at INTEGER
                )
            """)
            
            # Conversations (aggregated view)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    contact_id TEXT PRIMARY KEY,
                    last_message TEXT,
                    last_message_time INTEGER,
                    unread_count INTEGER DEFAULT 0,
                    created_at INTEGER
                )
            """)
            
            # Seen nonces (replay protection)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce TEXT PRIMARY KEY,
                    seen_at INTEGER
                )
            """)
            
            # Trusted keys cache
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_keys (
                    user_id TEXT PRIMARY KEY,
                    identity_key TEXT,
                    fingerprint TEXT,
                    verified INTEGER DEFAULT 0,  -- 0 = not verified, 1 = verified
                    first_seen INTEGER,
                    last_seen INTEGER
                )
            """)
            
            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_nonces_time ON seen_nonces(seen_at)")
    
    def get_identity(self):
        with self.get_connection() as conn:
            result = conn.execute("SELECT * FROM identity WHERE id = 1").fetchone()
            if result:
                # Parse JSON one-time prekeys if present
                identity = dict(result)
                if identity.get('one_time_prekeys'):
                    identity['one_time_prekeys'] = json.loads(identity['one_time_prekeys'])
                return identity
            return None
    
    def save_identity(self, user_id, identity_private_key, identity_public_key, 
                      signed_prekey, prekey_signature, one_time_prekeys, totp_secret):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO identity 
                (id, user_id, identity_private_key, identity_public_key, signed_prekey, 
                 prekey_signature, one_time_prekeys, totp_secret, created_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, identity_private_key, identity_public_key, signed_prekey,
                  prekey_signature, json.dumps(one_time_prekeys), totp_secret, int(datetime.now().timestamp())))
    
    def save_session(self, contact_id, session_id, send_chain_key, recv_chain_key,
                     send_header_key, recv_header_key):
        now = int(datetime.now().timestamp())
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sessions
                (contact_id, session_id, send_chain_key, recv_chain_key,
                 send_header_key, recv_header_key, created_at, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (contact_id, session_id, send_chain_key, recv_chain_key,
                  send_header_key, recv_header_key, now, now))
    
    def get_session(self, contact_id, session_id=None):
        with self.get_connection() as conn:
            if session_id:
                return conn.execute("""
                    SELECT * FROM sessions WHERE contact_id = ? AND session_id = ?
                """, (contact_id, session_id)).fetchone()
            else:
                return conn.execute("""
                    SELECT * FROM sessions WHERE contact_id = ? 
                    ORDER BY last_used DESC LIMIT 1
                """, (contact_id,)).fetchone()
    
    def save_message(self, message_id, conversation_id, sender_id, receiver_id, 
                     content, direction, ttl_seconds):
        now = int(datetime.now().timestamp())
        expires_at = now + ttl_seconds if ttl_seconds else None
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO messages
                (message_id, conversation_id, sender_id, receiver_id, content,
                 direction, status, ttl_seconds, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (message_id, conversation_id, sender_id, receiver_id, content,
                  direction, 'pending' if direction == 'sent' else 'delivered',
                  ttl_seconds, expires_at, now))
    
    def update_message_status(self, message_id, status):
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE messages SET status = ?, delivered_at = ? WHERE message_id = ?
            """, (status, int(datetime.now().timestamp()), message_id))
    
    def update_conversation(self, contact_id, message_content, is_from_contact):
        now = int(datetime.now().timestamp())
        with self.get_connection() as conn:
            existing = conn.execute("SELECT * FROM conversations WHERE contact_id = ?", (contact_id,)).fetchone()
            if existing:
                unread_delta = 1 if is_from_contact else 0
                conn.execute("""
                    UPDATE conversations 
                    SET last_message = ?, last_message_time = ?, unread_count = unread_count + ?
                    WHERE contact_id = ?
                """, (message_content, now, unread_delta, contact_id))
            else:
                conn.execute("""
                    INSERT INTO conversations (contact_id, last_message, last_message_time, unread_count)
                    VALUES (?, ?, ?, ?)
                """, (contact_id, message_content, now, 1 if is_from_contact else 0))
    
    def mark_conversation_read(self, contact_id):
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE conversations SET unread_count = 0 WHERE contact_id = ?
            """, (contact_id,))
    
    def is_nonce_seen(self, nonce):
        with self.get_connection() as conn:
            result = conn.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,)).fetchone()
            if result:
                return True
            # Clean old nonces (older than 5 minutes)
            cutoff = int(datetime.now().timestamp()) - 300
            conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?", (cutoff,))
            conn.execute("INSERT INTO seen_nonces (nonce, seen_at) VALUES (?, ?)", (nonce, int(datetime.now().timestamp())))
            return False
    
    def get_expired_messages(self):
        now = int(datetime.now().timestamp())
        with self.get_connection() as conn:
            return conn.execute("""
                SELECT * FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?
            """, (now,)).fetchall()
    
    def delete_messages(self, message_ids):
        with self.get_connection() as conn:
            placeholders = ','.join(['?'] * len(message_ids))
            conn.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", message_ids)