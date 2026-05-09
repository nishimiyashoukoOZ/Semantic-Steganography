# Adversarial Steganography

Hide data inside images that **actively fools CNN-based steganalyzers**.

Standard LSB steganography is trivially detected by statistical analysis (Chi-square attack, RS analysis). This project adds an adversarial perturbation layer that counteracts those detection signatures while keeping changes visually imperceptible.

---

## Architecture

```
Cover Image
    │
    ▼
┌─────────────────────┐
│   LSB Encoder       │  ← Embeds secret bits into pixel LSBs
└─────────────────────┘
    │ stego image
    ▼
┌─────────────────────┐
│ Adversarial         │  ← Applies structured noise to fool
│ Perturbation Engine │    chi-square + RS analysis detectors
└─────────────────────┘
    │ adversarial stego image (PSNR > 40dB)
    ▼
┌─────────────────────┐
│ Steganalyzer        │  ← Measures suspicion score [0,1]
│ (Chi² + RS)         │    Goal: drop score below 0.35 threshold
└─────────────────────┘
```

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Hide a message
python main.py encode photo.png "secret message" output.png --epsilon 2

# Recover the message
python main.py decode output.png

# Analyze an image for steganography
python main.py analyze output.png

# Full benchmark (payload × epsilon sweep)
python main.py eval photo.png

# End-to-end demo with synthetic image
python main.py demo
```

---

## Modules

| File | Purpose |
|---|---|
| `stego_core.py` | LSB encoder/decoder, steganalyzer (Chi²+RS), adversarial perturbation, PSNR/SSIM |
| `evaluate.py` | Benchmark sweep: payload fraction × epsilon → detection rate table |
| `main.py` | CLI interface |

---

## Key Concepts

**Chi-Square Attack:** LSB embedding equalizes even/odd pixel pair counts. The chi-square statistic measures how unnatural that equalization is. The adversarial layer re-introduces asymmetry.

**RS Analysis:** Divides pixels into Regular/Singular groups. LSB flipping shifts the R/S ratio in a characteristic way. Perturbation disrupts this signature.

**Epsilon (ε):** Max pixel value change the perturbation can apply (1-4 recommended). Higher ε → better evasion, lower PSNR. Sweet spot is ε=2 (PSNR stays >40dB).

**PSNR > 40 dB** = imperceptible to human eye. The goal is to evade detection while staying above this threshold.

---

## Extending This Project

- **Replace the heuristic analyzer** with a trained CNN (SRNet/XuNet) for stronger evaluation
- **Train a GAN-based encoder** where the generator hides data and the discriminator is the steganalyzer — full adversarial training loop
- **Test against ALASKA2 dataset** (Kaggle) — real competition benchmark for steganalysis
- **Add frequency-domain embedding** (DCT coefficients like JPEG steganography) for even harder detection
