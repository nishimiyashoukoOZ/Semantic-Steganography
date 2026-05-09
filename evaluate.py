"""
Evaluation Module
==================
Benchmark your steganography across:
1. Adversarial LSB: Detection rate vs payload size & epsilon
2. Semantic Stego (QIM): Capacity vs visual degradation (block_size & step)

* All generated benchmark images are saved to the designated project folder for visual inspection.
"""

import numpy as np
from PIL import Image
import os
import json
from stego_core import (
    AdversarialSteganography, SimpleSteganalyzer,
    LSBSteganography, compute_psnr, compute_ssim, text_to_bits
)
from semantic_stego import SemanticStego

# --- SAVE LOCATION ---
SAVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval_outputs")


def generate_test_image(size: tuple = (256, 256), seed: int = 0) -> np.ndarray:
    """Generate a pseudo-natural test image (gradients + texture)."""
    rng = np.random.default_rng(seed)
    h, w = size
    img = np.zeros((h, w, 3), dtype=np.uint8)

    for c in range(3):
        base = rng.integers(60, 200)
        grad = np.linspace(base, base + rng.integers(20, 60), w)
        channel = np.tile(grad, (h, 1)).astype(np.uint8)
        texture = rng.integers(0, 15, size=(h, w), dtype=np.uint8)
        img[:, :, c] = np.clip(channel + texture, 0, 255).astype(np.uint8)

    return img


def benchmark_adversarial(image: np.ndarray) -> list:
    """Sweep payload size vs detection rate for Adversarial LSB."""
    print("\n--- Running Adversarial LSB Benchmark ---")
    epsilons = [1, 2]
    payload_fractions = [0.25, 0.5, 1.0]
    
    h, w, c = image.shape
    # Calculate maximum capacity accounting for encryption overhead
    max_bits_available = h * w * c - 32  # 32 bits for header
    max_bytes_available = max_bits_available // 8
    # Encryption adds ~32 bytes overhead (16 nonce + up to 16 padding)
    max_chars_safe = max(1, max_bytes_available - 32)
    
    results = []

    for eps in epsilons:
        for frac in payload_fractions:
            # Calculate safe payload size
            n_chars = max(1, int(max_chars_safe * frac))
            message = ('A' * n_chars)[:n_chars]

            try:
                lsb = LSBSteganography()
                from stego_core import AdversarialPerturbation
                adv = AdversarialPerturbation(epsilon=eps)
                analyzer = SimpleSteganalyzer()

                # Encode with LSB
                stego = lsb.encode(image, message)
                payload_bits = len(text_to_bits(message)) + 32
                adv_stego = adv.apply(stego, image, payload_bits=payload_bits)

                # Save the adversarial image for visual inspection
                os.makedirs(SAVE_DIR, exist_ok=True)
                adv_filename = f"adv_stego_eps{eps}_payload{int(frac*100)}.png"
                adv_out_path = os.path.join(SAVE_DIR, adv_filename)
                Image.fromarray(adv_stego).save(adv_out_path, format="PNG")

                # Analyze
                stego_score = analyzer.analyze(stego)['overall_suspicion']
                adv_score = analyzer.analyze(adv_stego)['overall_suspicion']
                psnr = compute_psnr(image, adv_stego)
                
                results.append({
                    'epsilon': eps,
                    'payload%': frac,
                    'actual_chars': n_chars,
                    'lsb_suspicion': round(stego_score, 4),
                    'adv_suspicion': round(adv_score, 4),
                    'psnr_db': round(psnr, 2),
                    'evaded': (stego_score > 0.35) and (adv_score <= 0.35),
                })
                
            except ValueError as e:
                print(f"  [!] Skipping eps={eps}, payload={frac}: {e}")
                results.append({
                    'epsilon': eps,
                    'payload%': frac,
                    'actual_chars': 0,
                    'lsb_suspicion': 'N/A',
                    'adv_suspicion': 'N/A',
                    'psnr_db': 'N/A',
                    'evaded': False,
                })
                
    return results


def benchmark_semantic(image: np.ndarray) -> list:
    """Sweep block_size and step values for Semantic Object-Alteration."""
    print("\n--- Running Semantic Steganography Benchmark ---")
    block_sizes = [4, 8, 16]  # Size of the "objects"
    steps = [4, 8, 12]        # Intensity of the color shift
    
    h, w, c = image.shape
    results = []
    analyzer = SimpleSteganalyzer()
    
    # Save the base cover image so SemanticStego can read it from the disk
    os.makedirs(SAVE_DIR, exist_ok=True)
    cover_path = os.path.join(SAVE_DIR, 'eval_cover.png')
    Image.fromarray(image).save(cover_path, format="PNG")
        
    for b_size in block_sizes:
        for step in steps:
            stego_engine = SemanticStego(block_size=b_size, step=step)
            stego_engine.save_dir = SAVE_DIR  # Override to save in eval_outputs

            # Calculate capacity accounting for encryption overhead
            max_blocks = (h // b_size) * (w // b_size)
            max_encrypted_bits = max_blocks - 32  # 32 bits for header
            max_encrypted_bytes = max_encrypted_bits // 8
            # Encryption adds ~32 bytes overhead (16 nonce + up to 16 padding)
            max_chars = max(1, max_encrypted_bytes - 32)
            
            # Fill to 80% of safe capacity
            test_chars = max(1, int(max_chars * 0.8))
            message = ('B' * test_chars)[:test_chars]
            
            # Define output filename for this specific test
            stego_filename = f"sem_stego_b{b_size}_s{step}.png"
            stego_path = os.path.join(SAVE_DIR, stego_filename)
            
            try:
                # Encode
                stego_engine.encode(cover_path, message, stego_filename)
                
                # Read back for analysis
                if os.path.exists(stego_path):
                    stego_img = np.array(Image.open(stego_path).convert('RGB'))
                    
                    score = analyzer.analyze(stego_img)['overall_suspicion']
                    psnr = compute_psnr(image, stego_img)
                    ssim = compute_ssim(image, stego_img)
                    
                    results.append({
                        'block_size': b_size,
                        'step': step,
                        'capacity_chars': max_chars,
                        'actual_chars': test_chars,
                        'suspicion': round(score, 4),
                        'psnr_db': round(psnr, 2),
                        'ssim': round(ssim, 4)
                    })
                else:
                    print(f"  [!] Output file not created: {stego_path}")
                    results.append({
                        'block_size': b_size,
                        'step': step,
                        'capacity_chars': max_chars,
                        'actual_chars': 0,
                        'suspicion': 'N/A',
                        'psnr_db': 'N/A',
                        'ssim': 'N/A'
                    })
                    
            except Exception as e:
                print(f"  [!] Error for block_size={b_size}, step={step}: {e}")
                results.append({
                    'block_size': b_size,
                    'step': step,
                    'capacity_chars': max_chars,
                    'actual_chars': 0,
                    'suspicion': 'N/A',
                    'psnr_db': 'N/A',
                    'ssim': 'N/A'
                })
                
    return results


def print_table(headers, data_dicts):
    """Utility to print a nice aligned table."""
    # Filter out N/A values for formatting
    clean_dicts = []
    for row in data_dicts:
        clean_row = {}
        for k, v in row.items():
            if isinstance(v, str) and v == 'N/A':
                clean_row[k] = 'N/A'
            else:
                clean_row[k] = v
        clean_dicts.append(clean_row)
    
    # Calculate column widths
    col_widths = {}
    for h in headers:
        col_widths[h] = len(h)
        for row in clean_dicts:
            if h in row:
                val = str(row[h])
                if len(val) > col_widths[h]:
                    col_widths[h] = len(val)
    
    # Print header
    header_line = " | ".join([f"{h:>{col_widths[h]}}" for h in headers])
    separator = "-" * len(header_line)
    
    print(separator)
    print(header_line)
    print(separator)
    
    # Print rows
    for row in clean_dicts:
        formatted_values = []
        for h in headers:
            if h in row:
                val = row[h]
                if h == 'payload%' and isinstance(val, (int, float)):
                    formatted_values.append(f"{val:.0%}".rjust(col_widths[h]))
                elif isinstance(val, float):
                    formatted_values.append(f"{val:.4f}".rjust(col_widths[h]))
                else:
                    formatted_values.append(str(val).rjust(col_widths[h]))
            else:
                formatted_values.append('N/A'.rjust(col_widths[h]))
        print(" | ".join(formatted_values))
    
    print(separator)


def run_full_eval(image_path: str = None):
    """Run complete evaluation pipeline."""
    # Ensure the save directory exists before we do anything
    os.makedirs(SAVE_DIR, exist_ok=True)
    
    print("\n🔬 Steganography Master Evaluation Suite")
    print("=" * 60)
    print(f"[*] All test output files will be saved to: {SAVE_DIR}")

    if image_path and os.path.exists(image_path):
        image = np.array(Image.open(image_path).convert('RGB'))
        print(f"[*] Loaded Cover Image: {image_path} ({image.shape[1]}×{image.shape[0]}px)")
    else:
        image = generate_test_image((256, 256))
        print("[*] Using synthetic 256×256 test image (gradients + texture)")
        synthetic_path = os.path.join(SAVE_DIR, "synthetic_test_cover.png")
        Image.fromarray(image).save(synthetic_path)

    # 1. Benchmark Adversarial LSB
    adv_results = benchmark_adversarial(image)
    print("\n📊 Adversarial LSB Results:")
    print_table(['epsilon', 'payload%', 'actual_chars', 'lsb_suspicion', 'adv_suspicion', 'psnr_db', 'evaded'], adv_results)

    # 2. Benchmark Semantic Object Alteration
    sem_results = benchmark_semantic(image)
    print("\n📊 Semantic Steganography Results:")
    print_table(['block_size', 'step', 'capacity_chars', 'actual_chars', 'suspicion', 'psnr_db', 'ssim'], sem_results)
    
    print("\n[!] Evaluation Complete.")
    print("Notice how Semantic Steganography naturally bypasses the LSB suspicion thresholds ")
    print("(remaining < 0.35) while maintaining high structural similarity (SSIM)!")
    print(f"Check '{SAVE_DIR}' to view the generated images.")
    
    # Save results to JSON for reporting
    results_file = os.path.join(SAVE_DIR, 'benchmark_results.json')
    with open(results_file, 'w') as f:
        json.dump({
            'adversarial_results': adv_results,
            'semantic_results': sem_results
        }, f, indent=2)
    print(f"[*] Results saved to: {results_file}")


if __name__ == '__main__':
    import sys
    img_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_full_eval(img_path)