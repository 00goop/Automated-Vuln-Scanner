"""
MR-ROBOT Crypto Tools Module
Encoding/decoding, hash identification, and cipher operations.
"""
import base64
import hashlib
import binascii
import codecs
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import unquote, quote
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Hash patterns for identification
HASH_PATTERNS = {
    'MD5': (r'^[a-fA-F0-9]{32}$', 32),
    'SHA1': (r'^[a-fA-F0-9]{40}$', 40),
    'SHA256': (r'^[a-fA-F0-9]{64}$', 64),
    'SHA384': (r'^[a-fA-F0-9]{96}$', 96),
    'SHA512': (r'^[a-fA-F0-9]{128}$', 128),
    'NTLM': (r'^[a-fA-F0-9]{32}$', 32),
    'MySQL': (r'^\*[A-F0-9]{40}$', 41),
    'BCrypt': (r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$', None),
}


class CryptoTools:
    """
    Encryption, decoding, and hash utilities.
    """
    
    def decode(
        self,
        text: str,
        encoding: str,
        key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Decode text using specified encoding.
        
        Args:
            text: Input text to decode
            encoding: Encoding type (base64, hex, url, rot13, etc.)
            key: Optional key for ciphers
            
        Returns:
            Decoded result with metadata
        """
        encoding = encoding.lower().strip()
        
        try:
            if encoding == 'base64':
                result = self._decode_base64(text)
            elif encoding == 'hex':
                result = self._decode_hex(text)
            elif encoding == 'url':
                result = self._decode_url(text)
            elif encoding == 'rot13':
                result = self._decode_rot13(text)
            elif encoding == 'binary':
                result = self._decode_binary(text)
            elif encoding == 'caesar':
                result = self._decode_caesar(text, int(key) if key else None)
            elif encoding == 'xor':
                result = self._decode_xor(text, key or '')
            elif encoding == 'reverse':
                result = text[::-1]
            elif encoding == 'atbash':
                result = self._decode_atbash(text)
            else:
                return {
                    'success': False,
                    'error': f'Unknown encoding: {encoding}',
                    'supported': self.get_supported_encodings()
                }
            
            return {
                'success': True,
                'encoding': encoding,
                'input': text,
                'output': result,
                'length': len(result) if result else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'encoding': encoding
            }
    
    def encode(
        self,
        text: str,
        encoding: str,
        key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Encode text using specified encoding."""
        encoding = encoding.lower().strip()
        
        try:
            if encoding == 'base64':
                result = base64.b64encode(text.encode()).decode()
            elif encoding == 'hex':
                result = text.encode().hex()
            elif encoding == 'url':
                result = quote(text)
            elif encoding == 'rot13':
                result = codecs.encode(text, 'rot_13')
            elif encoding == 'binary':
                result = ' '.join(format(ord(c), '08b') for c in text)
            elif encoding == 'reverse':
                result = text[::-1]
            elif encoding == 'atbash':
                result = self._decode_atbash(text)  # Atbash is its own inverse
            else:
                return {
                    'success': False,
                    'error': f'Unknown encoding: {encoding}'
                }
            
            return {
                'success': True,
                'encoding': encoding,
                'input': text,
                'output': result
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def identify_hash(self, hash_string: str) -> Dict[str, Any]:
        """
        Identify the type of a hash.
        
        Args:
            hash_string: The hash to identify
            
        Returns:
            Possible hash types with confidence
        """
        hash_string = hash_string.strip()
        matches = []
        
        for hash_type, (pattern, expected_len) in HASH_PATTERNS.items():
            if re.match(pattern, hash_string):
                confidence = 'high' if len(hash_string) == expected_len else 'medium'
                matches.append({
                    'type': hash_type,
                    'confidence': confidence,
                    'length': len(hash_string)
                })
        
        if not matches:
            return {
                'success': True,
                'hash': hash_string,
                'identified': False,
                'message': 'Could not identify hash type',
                'length': len(hash_string)
            }
        
        return {
            'success': True,
            'hash': hash_string[:20] + '...' if len(hash_string) > 20 else hash_string,
            'identified': True,
            'possible_types': matches,
            'most_likely': matches[0]['type']
        }
    
    def generate_hash(self, text: str, algorithm: str = 'sha256') -> Dict[str, Any]:
        """Generate hash of text."""
        algorithm = algorithm.lower()
        
        try:
            if algorithm == 'md5':
                result = hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
            elif algorithm == 'sha1':
                result = hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()
            elif algorithm == 'sha256':
                result = hashlib.sha256(text.encode()).hexdigest()
            elif algorithm == 'sha384':
                result = hashlib.sha384(text.encode()).hexdigest()
            elif algorithm == 'sha512':
                result = hashlib.sha512(text.encode()).hexdigest()
            else:
                return {'success': False, 'error': f'Unknown algorithm: {algorithm}'}
            
            return {
                'success': True,
                'algorithm': algorithm.upper(),
                'input': text[:50] + '...' if len(text) > 50 else text,
                'hash': result
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def auto_decode(self, text: str) -> Dict[str, Any]:
        """
        Attempt to automatically detect and decode text.
        Tries multiple encodings and returns successful ones.
        """
        results = []
        
        # Try Base64
        try:
            decoded = self._decode_base64(text)
            if decoded and decoded.isprintable():
                results.append({
                    'encoding': 'base64',
                    'result': decoded,
                    'confidence': 'high' if len(decoded) > 3 else 'low'
                })
        except:
            pass
        
        # Try Hex
        try:
            decoded = self._decode_hex(text.replace(' ', ''))
            if decoded and decoded.isprintable():
                results.append({
                    'encoding': 'hex',
                    'result': decoded,
                    'confidence': 'high'
                })
        except:
            pass
        
        # Try URL decode
        try:
            decoded = self._decode_url(text)
            if decoded != text:
                results.append({
                    'encoding': 'url',
                    'result': decoded,
                    'confidence': 'high'
                })
        except:
            pass
        
        # Try ROT13
        decoded_rot13 = self._decode_rot13(text)
        if decoded_rot13 != text:
            # Check if result looks more like English
            results.append({
                'encoding': 'rot13',
                'result': decoded_rot13,
                'confidence': 'medium'
            })
        
        return {
            'success': True,
            'input': text[:100] + '...' if len(text) > 100 else text,
            'results': results,
            'count': len(results)
        }
    
    def get_supported_encodings(self) -> List[str]:
        """Get list of supported encodings."""
        return [
            'base64', 'hex', 'url', 'rot13', 'binary',
            'caesar', 'xor', 'reverse', 'atbash'
        ]
    
    # Private decode methods
    def _decode_base64(self, text: str) -> str:
        # Handle URL-safe base64
        text = text.replace('-', '+').replace('_', '/')
        # Add padding if needed
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode('utf-8', errors='replace')
    
    def _decode_hex(self, text: str) -> str:
        text = text.replace(' ', '').replace('0x', '').replace('\\x', '')
        return binascii.unhexlify(text).decode('utf-8', errors='replace')
    
    def _decode_url(self, text: str) -> str:
        return unquote(text)
    
    def _decode_rot13(self, text: str) -> str:
        return codecs.encode(text, 'rot_13')
    
    def _decode_binary(self, text: str) -> str:
        # Remove spaces and split into 8-bit chunks
        text = text.replace(' ', '')
        chunks = [text[i:i+8] for i in range(0, len(text), 8)]
        return ''.join(chr(int(chunk, 2)) for chunk in chunks if len(chunk) == 8)
    
    def _decode_caesar(self, text: str, shift: Optional[int] = None) -> str:
        """Caesar cipher decode. If no shift provided, try all 26."""
        if shift is not None:
            return self._caesar_shift(text, -shift)
        
        # Return all 26 possibilities
        results = []
        for s in range(1, 26):
            results.append(f"Shift {s}: {self._caesar_shift(text, -s)}")
        return '\n'.join(results)
    
    def _caesar_shift(self, text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    def _decode_xor(self, text: str, key: str) -> str:
        if not key:
            return "XOR requires a key"
        result = []
        for i, char in enumerate(text):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return ''.join(result)
    
    def _decode_atbash(self, text: str) -> str:
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(90 - (ord(char) - 65)))
                else:
                    result.append(chr(122 - (ord(char) - 97)))
            else:
                result.append(char)
        return ''.join(result)


# Export singleton
crypto_tools = CryptoTools()
