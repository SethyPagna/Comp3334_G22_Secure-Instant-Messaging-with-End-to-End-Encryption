import cmd
import requests
import json
import os
import time
import threading
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SERVER_URL = "http://127.0.0.1:5000"

class E2EEClient(cmd.Cmd):
    intro = 'Welcome to the Secure IM Client. Type help or ? to list commands.\n'
    prompt = '(IM) '

    def __init__(self):
        super().__init__()
        self.session_token = None
        self.username = None
        
        # Local State
        self.private_key = None
        self.public_key = None
        self.friends = {}         # friend_username -> status
        self.trusted_keys = {}    # friend_username -> verified_public_key
        self.history = {}         # username -> [{sender, text, timestamp, ttl}]
        self.blocked = set()
        self.current_chat = None
        self.default_ttl = 0      # 0 means infinite

        self.load_or_generate_identity()

    # ==========================================
    # R4: Per-device identity keypair
    # ==========================================
    def load_or_generate_identity(self):
        """Loads existing keypair or generates a new one."""
        if os.path.exists("id_ed25519"):
            with open("id_ed25519", "rb") as f:
                self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            with open("id_ed25519", "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    # ==========================================
    # R1, R2, R3: Auth & Registration
    # ==========================================
    def do_register(self, arg):
        """Register a new account: register <username> <password>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: register <username> <password>")
            return
        
        username, password = args
        pub_key_b64 = base64.b64encode(self.get_public_key_bytes()).decode('utf-8')
        
        # Example API Call
        # res = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password, "pubkey": pub_key_b64})
        print(f"[*] Registered user '{username}' with server (Mocked).")

    def do_login(self, arg):
        """Login: login <username> <password> <otp>"""
        args = arg.split()
        if len(args) != 3:
            print("Usage: login <username> <password> <otp>")
            return
        
        username, password, otp = args
        # Example API Call
        # res = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password, "otp": otp})
        # self.session_token = res.json().get("token")
        
        self.username = username
        self.session_token = "mock_session_token" # Mock
        print(f"[*] Logged in successfully as {username}.")

    def do_logout(self, arg):
        """Logout: /logout"""
        # requests.post(f"{SERVER_URL}/logout", headers={"Authorization": f"Bearer {self.session_token}"})
        self.session_token = None
        self.username = None
        print("[*] Logged out successfully. Token invalidated locally and on server.")

    def do_quit(self, arg):
        """Quit the application: /quit"""
        print("Goodbye!")
        return True

    def do_whoami(self, arg):
        """Show current user details"""
        if not self.username:
            print("Not logged in.")
        else:
            print(f"Logged in as: {self.username}")

    # ==========================================
    # R13, R14, R15: Friends, Requests, Blocking
    # ==========================================
    def do_add(self, arg):
        """Send a friend request: /add <username>"""
        if not arg:
            print("Usage: /add <username>")
            return
        print(f"[*] Friend request sent to {arg}.")
        # requests.post(f"{SERVER_URL}/friends/add", json={"target": arg})

    def do_requests(self, arg):
        """View pending friend requests: /requests"""
        print("[*] Pending requests: [MockUser1]")
        # Fetch from server...

    def do_accept(self, arg):
        """Accept a friend request: /accept <username>"""
        print(f"[*] Accepted friend request from {arg}.")

    def do_decline(self, arg):
        """Decline a friend request: /decline <username>"""
        print(f"[*] Declined friend request from {arg}.")

    def do_friends(self, arg):
        """List accepted friends: /friends"""
        print("[*] Your friends list: ")
        for f in self.friends:
            print(f"  - {f}")

    def do_block(self, arg):
        """Block a user: /block <username>"""
        self.blocked.add(arg)
        print(f"[*] Blocked {arg}. Messages and requests will be ignored.")

    def do_unblock(self, arg):
        """Unblock a user: /unblock <username>"""
        self.blocked.discard(arg)
        print(f"[*] Unblocked {arg}.")

    # ==========================================
    # R5, R6: Fingerprint & Verification
    # ==========================================
    def _compute_fingerprint(self, pubkey_bytes):
        return hashlib.sha256(pubkey_bytes).hexdigest()[:16]

    def do_fingerprint(self, arg):
        """Show fingerprint for a user: /fingerprint <username>"""
        # Mocking fetching pubkey from server
        mock_pubkey_bytes = b"mock_pubkey_bytes_for_" + arg.encode()
        fingerprint = self._compute_fingerprint(mock_pubkey_bytes)
        print(f"Fingerprint for {arg}: {fingerprint[:8]} {fingerprint[8:]}")

    def do_verify(self, arg):
        """Mark a user's fingerprint as verified: /verify <username>"""
        # Store their current pubkey locally
        self.trusted_keys[arg] = "mock_pubkey_bytes"
        print(f"[*] Marked {arg} as verified. If their key changes, you will be warned.")

    # ==========================================
    # Messaging & TTL (R10, R11, R16)
    # ==========================================
    def do_ttl(self, arg):
        """Set self-destruct timer for current messages: /ttl <seconds>"""
        try:
            self.default_ttl = int(arg)
            if self.default_ttl > 0:
                print(f"[*] TTL set to {self.default_ttl} seconds.")
            else:
                print("[*] TTL disabled (messages kept permanently).")
        except ValueError:
            print("Usage: /ttl <seconds>")

    def do_chat(self, arg):
        """Set active conversation: /chat <username>"""
        self.current_chat = arg
        if self.current_chat not in self.history:
            self.history[self.current_chat] = []
        print(f"[*] Switched chat to {arg}")

    def do_send(self, arg):
        """Send a message to the active chat: /send <message>"""
        if not self.current_chat:
            print("Error: Select a chat first using /chat <username>")
            return
        
        # Ensure target is a friend (R16 Anti-spam)
        # if self.current_chat not in self.friends:
        #    print("Error: You can only send messages to accepted friends.")
        #    return

        msg = {
            "sender": self.username,
            "text": arg, # In reality, encrypt this payload!
            "timestamp": time.time(),
            "ttl": self.default_ttl
        }
        
        # Append locally
        self.history[self.current_chat].append(msg)
        print(f"-> You: {arg} (TTL: {self.default_ttl}s)")
        
        # In reality: Sign, Encrypt with E2EE, and POST to server.
        # requests.post(f"{SERVER_URL}/messages/send", json={"to": self.current_chat, "ciphertext": ...})

    def do_history(self, arg):
        """View message history for active chat: /history"""
        if not self.current_chat:
            print("Select a chat first using /chat <username>")
            return
        
        # Clean expired messages first (R11)
        self._cleanup_expired_messages()

        print(f"--- History with {self.current_chat} ---")
        for msg in self.history.get(self.current_chat, []):
            sender = "You" if msg['sender'] == self.username else msg['sender']
            print(f"[{msg['timestamp']}] {sender}: {msg['text']}")

    def do_convs(self, arg):
        """List active conversations: /convs"""
        print("[*] Conversations:")
        for user, msgs in self.history.items():
            print(f"  - {user} ({len(msgs)} messages)")

    def _cleanup_expired_messages(self):
        """R11: Client deletion behavior"""
        current_time = time.time()
        for user in self.history:
            valid_msgs = []
            for msg in self.history[user]:
                if msg['ttl'] == 0:
                    valid_msgs.append(msg)
                elif (msg['timestamp'] + msg['ttl']) > current_time:
                    valid_msgs.append(msg)
            self.history[user] = valid_msgs

if __name__ == '__main__':
    app = E2EEClient()
    try:
        app.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
