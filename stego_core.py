import numpy as np
from PIL import Image
import math
import os
import hashlib
import secrets
from scipy.stats import chi2
from scipy.ndimage import sobel

# ------------------------------------------------------------
#  Encryption using hashlib (SHA-256 CTR mode)
# ------------------------------------------------------------
DEFAULT_KEY = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00' \
              b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

def text_to_bits(text: str) -> list:
    """Convert a UTF-8 string to a list of bits."""
    bits = []
    for byte in text.encode('utf-8'):
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_text(bits: list) -> str:
    """Convert a list of bits back to a UTF-8 string."""
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        chars.append(chr(byte))
    return ''.join(chars)

def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits back to bytes."""
    byte_list = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        byte_list.append(byte)
    return bytes(byte_list)

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

def compute_psnr(img1: np.ndarray, img2: np.ndarray) -> float:
    """Peak Signal-to-Noise Ratio (PSNR)."""
    mse = np.mean((img1.astype(float) - img2.astype(float)) ** 2)
    if mse == 0:
        return float("inf")
    return 20 * math.log10(255.0 / math.sqrt(mse))

def compute_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """Simplified Structural Similarity (SSIM) for RGB images."""
    C1 = (0.01 * 255) ** 2
    C2 = (0.03 * 255) ** 2
    img1 = img1.astype(float)
    img2 = img2.astype(float)
    mu1 = np.mean(img1, axis=(0, 1))
    mu2 = np.mean(img2, axis=(0, 1))
    sigma1_sq = np.var(img1, axis=(0, 1))
    sigma2_sq = np.var(img2, axis=(0, 1))
    sigma12 = np.mean((img1 - mu1) * (img2 - mu2), axis=(0, 1))
    ssim_map = ((2 * mu1 * mu2 + C1) * (2 * sigma12 + C2)) / (
        (mu1**2 + mu2**2 + C1) * (sigma1_sq + sigma2_sq + C2)
    )
    return float(np.mean(ssim_map))

# ------------------------------------------------------------
#  LSB Steganography (with encryption)
# ------------------------------------------------------------
class LSBSteganography:
    """LSB embedding with SHA-256 CTR encryption before hiding."""
    header_bits = 32

    def __init__(self, key: bytes = DEFAULT_KEY):
        self.key = key

    def encode(self, image: np.ndarray, message: str) -> np.ndarray:
        """Encrypt the message, then embed the ciphertext into pixel LSBs."""
        h, w, c = image.shape

        # Encrypt the plaintext
        encrypted_bytes = encrypt_message(message, self.key)

        # Convert encrypted bytes to bits
        payload_bits_list = bytes_to_bits(encrypted_bytes)

        total_bits = self.header_bits + len(payload_bits_list)
        max_bits = h * w * c
        if total_bits > max_bits:
            raise ValueError(f"Payload too large: {total_bits} bits needed, {max_bits} available")

        # Create 32-bit header: length of the encrypted payload in bits
        length_bits = [(len(payload_bits_list) >> i) & 1 for i in range(31, -1, -1)]
        all_bits = length_bits + payload_bits_list

        stego = image.copy().astype(int)
        bit_idx = 0
        for ch in range(c):
            for y in range(h):
                for x in range(w):
                    if bit_idx >= len(all_bits):
                        break
                    stego[y, x, ch] = (stego[y, x, ch] & 0xFE) | all_bits[bit_idx]
                    bit_idx += 1
                if bit_idx >= len(all_bits):
                    break
            if bit_idx >= len(all_bits):
                break
        return stego.astype(np.uint8)

    def decode(self, image: np.ndarray) -> str:
        """Extract LSB bits, reconstruct the encrypted payload, then decrypt it."""
        h, w, c = image.shape
        bits = []
        for ch in range(c):
            for y in range(h):
                for x in range(w):
                    bits.append(image[y, x, ch] & 1)

        # Read 32-bit header for payload length
        length = 0
        for i in range(32):
            length = (length << 1) | bits[i]
        if length <= 0 or length > len(bits) - 32:
            return ""

        payload_bits = bits[32:32 + length]
        encrypted_bytes = bits_to_bytes(payload_bits)

        try:
            return decrypt_message(encrypted_bytes, self.key)
        except:
            return ""

# ------------------------------------------------------------
#  Chi-Square + RS Analyser
# ------------------------------------------------------------
class SimpleSteganalyzer:
    """Combines Chi-square attack on LSB pairs and simplified RS-like gradient check."""

    def analyze(self, image: np.ndarray):
        h, w, c = image.shape
        
        # Chi-square on LSB pairs
        chi_scores = []
        for ch in range(c):
            hist = np.histogram(image[:, :, ch], bins=256, range=(0, 255))[0]
            pairs = [(hist[i], hist[i + 1]) for i in range(0, 256, 2)]
            chi2_val = 0.0
            dof = 0
            for n0, n1 in pairs:
                expected = (n0 + n1) / 2.0
                if expected > 0:
                    chi2_val += (n0 - expected) ** 2 / expected + (n1 - expected) ** 2 / expected
                    dof += 1
            if dof > 0:
                p = 1 - chi2.cdf(chi2_val, dof)
            else:
                p = 1.0
            chi_scores.append(p)
        chi_suspicion = 1 - np.mean(chi_scores)

        # RS-like gradient difference
        gray = np.mean(image, axis=2).astype(float)
        grad_orig = sobel(gray)
        flipped = gray.copy()
        flipped += (flipped.astype(int) & 1) ^ 1
        grad_flip = sobel(flipped)
        diff = np.abs(grad_orig - grad_flip).mean()
        rs_suspicion = min(1.0, diff / 2.0)

        overall = 0.7 * chi_suspicion + 0.3 * rs_suspicion
        overall = round(min(1.0, max(0.0, overall)), 4)

        if overall < 0.25:
            verdict, confidence = "Clean", "High"
        elif overall < 0.5:
            verdict, confidence = "Suspicious", "Moderate"
        elif overall < 0.75:
            verdict, confidence = "Probably Stego", "Moderate"
        else:
            verdict, confidence = "Stego Detected", "High"

        return {
            "overall_suspicion": overall,
            "verdict": verdict,
            "confidence": confidence,
        }

# ------------------------------------------------------------
#  Adversarial Perturbation (preserves LSBs)
# ------------------------------------------------------------
class AdversarialPerturbation:
    """Adds small structured noise to break LSB statistical signature while keeping PSNR high."""
    
    def __init__(self, epsilon=2):
        self.epsilon = epsilon

    def apply(self, stego: np.ndarray, original: np.ndarray, payload_bits: int = 0) -> np.ndarray:
        """Add random even-valued noise within [-epsilon, epsilon] to preserve LSBs."""
        choices = [0] + [2 * i for i in range(1, self.epsilon // 2 + 1)]
        choices = sorted(choices + [-x for x in choices])
        rng = np.random.default_rng(seed=42)
        noise = rng.choice(choices, size=stego.shape)
        adv = stego.astype(int) + noise
        return np.clip(adv, 0, 255).astype(np.uint8)

# ------------------------------------------------------------
#  Adversarial Steganography Pipeline
# ------------------------------------------------------------
class AdversarialSteganography:
    """Full pipeline: LSB encode → adversarial perturbation → save → analyze."""
    
    def __init__(self, epsilon=2, key: bytes = DEFAULT_KEY):
        self.epsilon = epsilon
        self.lsb = LSBSteganography(key=key)
        self.perturbation = AdversarialPerturbation(epsilon=epsilon)
        self.analyzer = SimpleSteganalyzer()

    def encode(self, img_path: str, message: str, output_path: str):
        """Full encode pipeline."""
        cover = Image.open(img_path).convert("RGB")
        img_array = np.array(cover)

        # LSB encode (with encryption inside)
        stego_array = self.lsb.encode(img_array, message)

        # Apply adversarial perturbation
        payload_bits = len(text_to_bits(message)) + 32
        adv_array = self.perturbation.apply(stego_array, img_array, payload_bits)

        # Save result
        Image.fromarray(adv_array).save(output_path)

        # Analysis
        analysis = {
            "original": self.analyzer.analyze(img_array),
            "after_lsb": self.analyzer.analyze(stego_array),
            "after_adversarial": self.analyzer.analyze(adv_array),
        }
        analysis["original"]["image"] = img_array
        analysis["after_lsb"]["image"] = stego_array
        analysis["after_adversarial"]["image"] = adv_array

        evasion = {
            "lsb_detected": analysis["after_lsb"]["overall_suspicion"] > 0.35,
            "adversarial_detected": analysis["after_adversarial"]["overall_suspicion"] > 0.35,
        }
        return {"analysis": analysis, "evasion": evasion}

    def decode(self, img_path: str) -> str:
        """Extract and decrypt message from stego image."""
        img = Image.open(img_path).convert("RGB")
        arr = np.array(img)
        return self.lsb.decode(arr)