#!/usr/bin/env python3
"""
Semantic Object-Alteration Steganography with Built-in Encryption
==================================================================
Uses SHA-256 CTR mode encryption (no external crypto libraries needed).
"""

import sys, os, numpy as np
from PIL import Image
import hashlib, secrets

# ------------------------------------------------------------
#  Encryption (same as stego_core.py)
# ------------------------------------------------------------
DEFAULT_KEY = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00' \
              b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

def encrypt_message(message: str, key: bytes = DEFAULT_KEY) -> bytes:
    """SHA-256 CTR mode encryption."""
    nonce = secrets.token_bytes(16)
    data = message.encode('utf-8')
    encrypted = bytearray()
    counter = 0
    while len(encrypted) < len(data):
        keystream_input = key + nonce + counter.to_bytes(8, 'big')
        keystream = hashlib.sha256(keystream_input).digest()
        for i in range(len(keystream)):
            if len(encrypted) >= len(data):
                break
            encrypted.append(data[len(encrypted)] ^ keystream[i])
        counter += 1
    return nonce + bytes(encrypted)

def decrypt_message(encrypted_data: bytes, key: bytes = DEFAULT_KEY) -> str:
    """SHA-256 CTR mode decryption."""
    if len(encrypted_data) < 16:
        return ""
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    decrypted = bytearray()
    counter = 0
    while len(decrypted) < len(ciphertext):
        keystream_input = key + nonce + counter.to_bytes(8, 'big')
        keystream = hashlib.sha256(keystream_input).digest()
        for i in range(len(keystream)):
            if len(decrypted) >= len(ciphertext):
                break
            decrypted.append(ciphertext[len(decrypted)] ^ keystream[i])
        counter += 1
    try:
        return bytes(decrypted).decode('utf-8')
    except:
        return ""

def bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: list) -> bytes:
    byte_list = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        byte_list.append(byte)
    return bytes(byte_list)

# ------------------------------------------------------------
#  Semantic Stego with Encryption
# ------------------------------------------------------------
class SemanticStego:
    def __init__(self, block_size=8, step=8, key: bytes = DEFAULT_KEY):
        self.block_size = block_size
        self.step = step
        self.header_bits = 32
        self.key = key
        self.save_dir = "outputs"

    def encode(self, img_path, message, out_filename):
        print(f"[*] Loading cover image: {img_path}")
        img = Image.open(img_path).convert("RGB")
        arr = np.array(img).astype(float)
        h, w, _ = arr.shape

        # Encrypt the message
        encrypted_bytes = encrypt_message(message, self.key)
        payload_bits = bytes_to_bits(encrypted_bytes)

        max_blocks = (h // self.block_size) * (w // self.block_size)
        total_bits_needed = self.header_bits + len(payload_bits)
        if total_bits_needed > max_blocks:
            max_chars = (max_blocks - self.header_bits) // 8
            print(f"[!] Error: Message too long! Max capacity is {max_chars} characters.")
            return

        # Create header
        length_bits = [(len(payload_bits) >> (31 - i)) & 1 for i in range(32)]
        all_bits = length_bits + payload_bits

        bit_idx = 0
        target_channel = 2

        print(f"[*] Encrypting & encoding {len(message)} characters via block-colour alteration...")
        for y in range(0, h - self.block_size + 1, self.block_size):
            for x in range(0, w - self.block_size + 1, self.block_size):
                if bit_idx >= len(all_bits):
                    break
                block = arr[y:y+self.block_size, x:x+self.block_size, target_channel]
                avg = np.mean(block)
                target_bit = all_bits[bit_idx]
                quantized_bucket = round(avg / self.step)
                if quantized_bucket % 2 != target_bit:
                    if avg > quantized_bucket * self.step:
                        quantized_bucket += 1
                    else:
                        quantized_bucket -= 1
                new_avg = quantized_bucket * self.step
                delta = new_avg - avg
                arr[y:y+self.block_size, x:x+self.block_size, target_channel] += delta
                bit_idx += 1

        os.makedirs(self.save_dir, exist_ok=True)
        final_out_path = os.path.join(self.save_dir, os.path.basename(out_filename))
        arr = np.clip(arr, 0, 255).astype(np.uint8)
        Image.fromarray(arr).save(final_out_path, format="PNG")
        print(f"[+] Success! Image saved to: {final_out_path}")

    def decode(self, img_path):
        print(f"[*] Analyzing block colours in: {img_path}")
        img = Image.open(img_path).convert("RGB")
        arr = np.array(img).astype(float)
        h, w, _ = arr.shape
        target_channel = 2
        extracted_bits = []
        for y in range(0, h - self.block_size + 1, self.block_size):
            for x in range(0, w - self.block_size + 1, self.block_size):
                block = arr[y:y+self.block_size, x:x+self.block_size, target_channel]
                avg = np.mean(block)
                quantized_bucket = round(avg / self.step)
                extracted_bits.append(int(quantized_bucket % 2))

        header_bits = extracted_bits[:self.header_bits]
        msg_length = 0
        for b in header_bits:
            msg_length = (msg_length << 1) | b
        if msg_length <= 0 or msg_length > len(extracted_bits) - self.header_bits:
            print("[-] No valid hidden message found.")
            return

        msg_bits = extracted_bits[self.header_bits:self.header_bits + msg_length]
        encrypted_bytes = bits_to_bytes(msg_bits)

        try:
            message = decrypt_message(encrypted_bytes, self.key)
            print(f"\n[+] Decrypted Message:\n{'-'*20}\n{message}\n{'-'*20}")
        except:
            print("[-] Decryption failed. Possibly wrong key or corrupted data.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python semantic_stego.py encode <image.png> <message> <output_filename.png>")
        print("  python semantic_stego.py decode <stego_image.png>")
        sys.exit(1)
    cmd = sys.argv[1].lower()
    stego = SemanticStego(block_size=8, step=8)
    if cmd == "encode" and len(sys.argv) >= 5:
        stego.encode(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "decode" and len(sys.argv) >= 3:
        stego.decode(sys.argv[2])
    else:
        print("Invalid arguments.")