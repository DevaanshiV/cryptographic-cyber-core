# app.py
import os
import json
import hashlib
import random
import math
import struct
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ============================
# Symmetric Cipher (TEA)
# ============================
class TEA:
    """Tiny Encryption Algorithm – 64-bit block, 128-bit key."""
    DELTA = 0x9E3779B9
    ROUNDS = 32

    @staticmethod
    def _pad(data: bytes, block_size: int = 8) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 8:
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    @classmethod
    def _derive_key(cls, passphrase: str) -> bytes:
        """Derive 128-bit key from passphrase using SHA-256."""
        return hashlib.sha256(passphrase.encode('utf-8')).digest()[:16]

    @classmethod
    def _encrypt_block(cls, block: bytes, key: bytes) -> bytes:
        """Encrypt a single 64-bit block (8 bytes)."""
        if len(block) != 8 or len(key) != 16:
            raise ValueError("Block must be 8 bytes, key 16 bytes")
        v0, v1 = struct.unpack('>II', block)
        k0, k1, k2, k3 = struct.unpack('>IIII', key)
        s = 0
        for _ in range(cls.ROUNDS):
            s = (s + cls.DELTA) & 0xFFFFFFFF
            v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        return struct.pack('>II', v0, v1)

    @classmethod
    def _decrypt_block(cls, block: bytes, key: bytes) -> bytes:
        """Decrypt a single 64-bit block (8 bytes)."""
        if len(block) != 8 or len(key) != 16:
            raise ValueError("Block must be 8 bytes, key 16 bytes")
        v0, v1 = struct.unpack('>II', block)
        k0, k1, k2, k3 = struct.unpack('>IIII', key)
        s = cls.DELTA * cls.ROUNDS & 0xFFFFFFFF
        for _ in range(cls.ROUNDS):
            v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            s = (s - cls.DELTA) & 0xFFFFFFFF
        return struct.pack('>II', v0, v1)

    @classmethod
    def encrypt(cls, plaintext: str, passphrase: str) -> bytes:
        """Encrypt plaintext string using TEA with passphrase-derived key."""
        key = cls._derive_key(passphrase)
        data = plaintext.encode('utf-8')
        padded = cls._pad(data, 8)
        cipher = b''
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            cipher += cls._encrypt_block(block, key)
        return cipher

    @classmethod
    def decrypt(cls, ciphertext: bytes, passphrase: str) -> str:
        """Decrypt ciphertext bytes using TEA with passphrase-derived key."""
        if len(ciphertext) % 8 != 0:
            raise ValueError("Ciphertext length must be multiple of 8")
        key = cls._derive_key(passphrase)
        plain_padded = b''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            plain_padded += cls._decrypt_block(block, key)
        plain = cls._unpad(plain_padded)
        return plain.decode('utf-8')


# ============================
# RSA Key Pair Generator
# ============================
def is_prime(n: int, k: int = 40) -> bool:
    """Miller–Rabin primality test with k rounds."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    # write n-1 as d*2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Generate a prime number of given bit length."""
    while True:
        p = random.getrandbits(bits)
        # Ensure highest and lowest bits set for proper length and oddness
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def egcd(a: int, b: int) -> tuple:
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def generate_rsa_keypair(bits: int = 256) -> dict:
    """
    Generate RSA public/private key pair.
    Returns dict with 'public' and 'private' keys (hex strings).
    """
    # Ensure bits is even and at least 128
    if bits < 128 or bits % 2 != 0:
        bits = 256
    prime_bits = bits // 2
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return {
        'public': {
            'n': hex(n)[2:],
            'e': hex(e)[2:]
        },
        'private': {
            'n': hex(n)[2:],
            'd': hex(d)[2:]
        }
    }


# ============================
# Flask Routes
# ============================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/symmetric/encrypt', methods=['POST'])
def symmetric_encrypt():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    plaintext = data.get('plaintext')
    passphrase = data.get('passphrase')
    if plaintext is None or passphrase is None:
        return jsonify({'error': 'Missing plaintext or passphrase'}), 400
    try:
        cipher_bytes = TEA.encrypt(plaintext, passphrase)
        cipher_hex = cipher_bytes.hex()
        return jsonify({'ciphertext_hex': cipher_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/symmetric/decrypt', methods=['POST'])
def symmetric_decrypt():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    cipher_hex = data.get('ciphertext_hex')
    passphrase = data.get('passphrase')
    if cipher_hex is None or passphrase is None:
        return jsonify({'error': 'Missing ciphertext_hex or passphrase'}), 400
    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        plaintext = TEA.decrypt(cipher_bytes, passphrase)
        return jsonify({'plaintext': plaintext})
    except ValueError as e:
        return jsonify({'error': f'Invalid hex or padding: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/rsa/generate', methods=['POST'])
def rsa_generate():
    data = request.get_json() or {}
    key_size = data.get('key_size', 256)
    try:
        key_size = int(key_size)
    except ValueError:
        key_size = 256
    try:
        keys = generate_rsa_keypair(key_size)
        return jsonify(keys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)