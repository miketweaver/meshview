import base64
import threading
from typing import List, Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from google.protobuf.message import DecodeError


class KeyManager:
    """
    Manages multiple encryption keys for Meshtastic channel decryption.
    Provides caching to avoid re-testing keys for the same node/channel combinations.
    """
    
    def __init__(self, channel_keys: List[str]):
        """
        Initialize the key manager with a list of base64-encoded keys.
        
        Args:
            channel_keys: List of base64-encoded encryption keys
        """
        self.keys = []
        for key_str in channel_keys:
            try:
                key_bytes = base64.b64decode(key_str.strip())
                if len(key_bytes) in [16, 32]:  # AES-128 (16 bytes) or AES-256 (32 bytes)
                    self.keys.append(key_bytes)
                else:
                    print(f"Warning: Skipping invalid key length {len(key_bytes)} bytes (must be 16 or 32 bytes)")
            except Exception as e:
                print(f"Warning: Skipping invalid key '{key_str}': {e}")
        
        if not self.keys:
            raise ValueError("No valid encryption keys provided")
        
        # Cache for successful key mappings: (from_node_id, channel) -> key_index
        self._key_cache: Dict[Tuple[int, str], int] = {}
        self._cache_lock = threading.Lock()
        
        print(f"KeyManager initialized with {len(self.keys)} valid keys")
    
    def decrypt_packet(self, packet) -> bool:
        """
        Attempt to decrypt a packet using available keys.
        Uses caching to avoid re-testing keys for known node/channel combinations.
        
        Args:
            packet: The packet to decrypt
            
        Returns:
            True if decryption was successful, False otherwise
        """
        if packet.HasField("decoded"):
            return True
        
        from_node_id = getattr(packet, "from", None)
        if from_node_id is None:
            return False
        
        # Try cached key first
        cache_key = (from_node_id, getattr(packet, 'channel', 'default'))
        with self._cache_lock:
            cached_key_index = self._key_cache.get(cache_key)
        
        if cached_key_index is not None:
            # Save original encrypted data
            original_encrypted = packet.encrypted
            if self._try_decrypt_with_key(packet, cached_key_index):
                return True
            else:
                # Restore encrypted data and remove from cache
                packet.encrypted = original_encrypted
                with self._cache_lock:
                    self._key_cache.pop(cache_key, None)
        
        # Try all keys
        # Save original encrypted data since decryption attempts might modify the packet
        original_encrypted = packet.encrypted
        for key_index, key in enumerate(self.keys):
            # Restore original encrypted data for each attempt
            packet.encrypted = original_encrypted
            if self._try_decrypt_with_key(packet, key_index):
                # Cache successful key mapping
                with self._cache_lock:
                    self._key_cache[cache_key] = key_index
                return True
        
        return False
    
    def _try_decrypt_with_key(self, packet, key_index: int) -> bool:
        """
        Try to decrypt a packet with a specific key.
        
        Args:
            packet: The packet to decrypt
            key_index: Index of the key to use
            
        Returns:
            True if decryption was successful, False otherwise
        """
        try:
            # Check if packet has encrypted data
            if not packet.encrypted:
                return False
                
            key = self.keys[key_index]
            packet_id = packet.id.to_bytes(8, "little")
            from_node_id = getattr(packet, "from").to_bytes(8, "little")
            nonce = packet_id + from_node_id

            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            raw_proto = decryptor.update(packet.encrypted) + decryptor.finalize()
            
            # Check if we got empty data - this might indicate wrong key
            if len(raw_proto) == 0:
                return False
            
            # Try to parse as protobuf
            packet.decoded.ParseFromString(raw_proto)
            return True
            
        except (DecodeError, Exception):
            # Reset the decoded field if parsing failed
            packet.ClearField("decoded")
            return False
    
    def get_key_count(self) -> int:
        """Return the number of available keys."""
        return len(self.keys)
    
    def clear_cache(self):
        """Clear the key cache. Useful for testing or when keys change."""
        with self._cache_lock:
            self._key_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Return cache statistics for monitoring."""
        with self._cache_lock:
            return {
                "cached_mappings": len(self._key_cache),
                "total_keys": len(self.keys)
            }


# Global key manager instance
_key_manager: Optional[KeyManager] = None


def initialize_key_manager(channel_keys: List[str]):
    """
    Initialize the global key manager with the provided keys.
    
    Args:
        channel_keys: List of base64-encoded encryption keys
    """
    global _key_manager
    _key_manager = KeyManager(channel_keys)


def get_key_manager() -> Optional[KeyManager]:
    """Get the global key manager instance."""
    return _key_manager


def decrypt_packet(packet) -> bool:
    """
    Decrypt a packet using the global key manager.
    Falls back to the original hardcoded key if no key manager is initialized.
    
    Args:
        packet: The packet to decrypt
        
    Returns:
        True if decryption was successful, False otherwise
    """
    if _key_manager:
        return _key_manager.decrypt_packet(packet)
    else:
        # Fallback to original behavior
        return _decrypt_with_default_key(packet)


def _decrypt_with_default_key(packet) -> bool:
    """
    Original decryption logic using the hardcoded default key.
    This is kept as a fallback for backward compatibility.
    """
    if packet.HasField("decoded"):
        return True
    
    try:
        # Original hardcoded key
        key = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")
        packet_id = packet.id.to_bytes(8, "little")
        from_node_id = getattr(packet, "from").to_bytes(8, "little")
        nonce = packet_id + from_node_id

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        raw_proto = decryptor.update(packet.encrypted) + decryptor.finalize()
        
        packet.decoded.ParseFromString(raw_proto)
        return True
        
    except (DecodeError, Exception):
        packet.ClearField("decoded")
        return False
