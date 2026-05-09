#!/usr/bin/env python3
"""
Master Steganography CLI
================================
Supports both Adversarial LSB and Semantic Object-Alteration (QIM).

Usage:
  python main.py encode <image> <message> [output] [--method adv|sem] [--epsilon N] [--block N] [--step N]
  python main.py decode <image> [--method adv|sem]
  python main.py analyze <image>
  python main.py eval [image]
  python main.py demo

Methods:
  adv : Adversarial LSB (default)
  sem : Semantic Object-Alteration

Examples:
  python main.py encode photo.png "secret" out.png --method sem --block 8 --step 12
  python main.py decode out.png --method sem
  python main.py eval photo.png
"""

import sys
import os
import numpy as np
from PIL import Image

# Core Modules
sys.path.insert(0, os.path.dirname(__file__))
from stego_core import AdversarialSteganography, SimpleSteganalyzer
from semantic_stego import SemanticStego
from evaluate import run_full_eval, generate_test_image

# --- HARDCODED SAVE LOCATION ---
SAVE_DIR = r"X:\files\cybersecurity projects\sg\Newfolder"


def resolve_path(filepath):
    """Helper to find the image either locally or in the target save directory."""
    if os.path.exists(filepath):
        return filepath
    target_path = os.path.join(SAVE_DIR, os.path.basename(filepath))
    if os.path.exists(target_path):
        return target_path
    return filepath  # Return original if not found, let it throw the standard error


def extract_arg(args, flag, default, arg_type=int):
    """Helper to extract command line arguments like --epsilon 2"""
    try:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return arg_type(args[idx + 1])
    except ValueError:
        pass
    return default


def cmd_encode(args):
    if len(args) < 2:
        print("Usage: python main.py encode <image> <message> [output.png] [--method adv|sem]")
        return

    image_path = resolve_path(args[0])
    message = args[1]
    
    # Determine Output Name
    out_name = args[2] if len(args) > 2 and not args[2].startswith('--') else 'output_stego.png'
    os.makedirs(SAVE_DIR, exist_ok=True)
    output_path = os.path.join(SAVE_DIR, os.path.basename(out_name))

    method = extract_arg(args, '--method', 'adv', str)

    if not os.path.exists(image_path):
        print(f"[!] Error: Cover image not found: {image_path}")
        return

    print(f"\n🔐 Encoding message ({len(message)} chars) into {os.path.basename(image_path)}")
    print(f"   Method: {'Semantic (QIM)' if method == 'sem' else 'Adversarial LSB'}")

    if method == 'sem':
        block_size = extract_arg(args, '--block', 8)
        step = extract_arg(args, '--step', 8)
        print(f"   Parameters: Block Size={block_size}, Step={step}")
        
        stego_engine = SemanticStego(block_size=block_size, step=step)
        # semantic_stego.py handles its own saving printouts
        stego_engine.encode(image_path, message, output_path)

    else:
        epsilon = extract_arg(args, '--epsilon', 2)
        print(f"   Parameters: Epsilon={epsilon}")
        
        pipeline = AdversarialSteganography(epsilon=epsilon)
        result = pipeline.encode(image_path, message, output_path)

        print(f"\n   Steganalysis Results:")
        a = result['analysis']
        for stage, key in [('Original', 'original'), ('LSB Only', 'after_lsb'), ('Adversarial', 'after_adversarial')]:
            score = a[key]['overall_suspicion']
            verdict = a[key]['verdict']
            bar = '█' * int(score * 20) + '░' * (20 - int(score * 20))
            print(f"   {stage:<12} [{bar}] {score:.4f}  {verdict}")
        
        e = result['evasion']
        if e['lsb_detected'] and not e['adversarial_detected']:
            print(f"   ✅ Evasion SUCCESS — adversarial perturbation fooled the detector!")
        
        print(f"\n   [+] Saved to: {output_path}")


def cmd_decode(args):
    if not args:
        print("Usage: python main.py decode <image> [--method adv|sem]")
        return

    image_path = resolve_path(args[0])
    method = extract_arg(args, '--method', 'adv', str)

    if not os.path.exists(image_path):
        print(f"[!] Error: Stego image not found: {image_path}")
        return

    print(f"\n🔓 Decoding from {os.path.basename(image_path)} using {'Semantic' if method == 'sem' else 'Adversarial'} method...")

    if method == 'sem':
        block_size = extract_arg(args, '--block', 8)
        step = extract_arg(args, '--step', 8)
        stego_engine = SemanticStego(block_size=block_size, step=step)
        stego_engine.decode(image_path)
    else:
        pipeline = AdversarialSteganography()
        message = pipeline.decode(image_path)
        if message:
            print(f"\n[+] Decoded message:\n{'-'*20}\n{message}\n{'-'*20}")
        else:
            print(f"\n[-] No hidden message found (or corrupted).")


def cmd_analyze(args):
    if not args:
        print("Usage: python main.py analyze <image>")
        return

    image_path = resolve_path(args[0])
    if not os.path.exists(image_path):
        print(f"[!] Error: Image not found: {image_path}")
        return

    img = np.array(Image.open(image_path).convert('RGB'))
    analyzer = SimpleSteganalyzer()
    result = analyzer.analyze(img)

    print(f"\n🔍 Steganalysis: {os.path.basename(image_path)}")
    score = result['overall_suspicion']
    bar = '█' * int(score * 30) + '░' * (30 - int(score * 30))
    print(f"   Overall Score: [{bar}] {score:.4f}")
    print(f"   Verdict: {result['verdict']} (confidence: {result['confidence']})")


def cmd_demo(args):
    """End-to-end demo showing off both systems."""
    print("\n🎬 Full Demo — Master Steganography Suite")
    print("="*60)
    
    os.makedirs(SAVE_DIR, exist_ok=True)

    # 1. Generate test image
    img_array = generate_test_image((256, 256), seed=12)
    demo_img = os.path.join(SAVE_DIR, 'demo_cover.png')
    Image.fromarray(img_array).save(demo_img)
    print(f"[*] Generated synthetic 256×256 cover image")

    secret = "The target server is located at 192.168.1.105. Use backdoor port 8080."
    print(f"[*] Secret message: \"{secret}\"")
    print()

    # 2. Demo Adversarial LSB
    print("--- 1. Testing Adversarial LSB ---")
    adv_out = os.path.join(SAVE_DIR, 'demo_adv_stego.png')
    cmd_encode([demo_img, secret, adv_out, '--method', 'adv', '--epsilon', '2'])
    print("\nDecoding Adversarial...")
    cmd_decode([adv_out, '--method', 'adv'])
    print("\n")

    # 3. Demo Semantic Object-Alteration
    print("--- 2. Testing Semantic Object-Alteration ---")
    sem_out = os.path.join(SAVE_DIR, 'demo_sem_stego.png')
    cmd_encode([demo_img, secret, sem_out, '--method', 'sem', '--block', '8', '--step', '8'])
    print("\nDecoding Semantic...")
    cmd_decode([sem_out, '--method', 'sem'])

    print(f"\n[!] Demo Complete. Check {SAVE_DIR} for output files.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    commands = {
        'encode': cmd_encode,
        'decode': cmd_decode,
        'analyze': cmd_analyze,
        'eval': lambda a: run_full_eval(resolve_path(a[0]) if a else None),
        'demo': cmd_demo,
    }

    if cmd in commands:
        commands[cmd](args)
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == '__main__':
    main()