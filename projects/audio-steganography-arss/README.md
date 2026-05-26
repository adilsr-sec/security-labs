# 🔊 Audio-in-Image Steganography — Arjuna's Astra (ARSS Algorithm)

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)](test_arss.py)
[![Domain](https://img.shields.io/badge/Domain-Steganography_•_Cryptography_•_Signal_Processing-blueviolet?style=flat-square)]()

> **Academic Capstone Project** — Steganography & Digital Watermarking

---

## 📌 Project Overview

**Arjuna's Astra** (ARSS — Arjuna's Astra Robust Steganography Scheme) is a custom steganographic algorithm designed to **embed audio waveform data invisibly inside digital images**.

The technique exploits the **human visual system's limited sensitivity to minor luminance changes**: by replacing the 1–4 Least-Significant Bits (LSBs) of each RGB pixel channel with encoded audio amplitude samples, we hide a covert audio payload in plain sight. The cover image appears visually identical to the human eye, but the embedded data can be extracted by anyone with knowledge of the ARSS scheme.

**Real-world relevance:** Steganography is used in:
- Digital watermarking for intellectual property protection.
- Covert communication in adversarial environments.
- Steganalysis (detecting hidden content) — a key skill for cyber forensics analysts.

---

## 🧠 Algorithm Design — ARSS

### Encoding Pipeline

```
INPUT: Cover Image (RGB PNG) + Audio Samples (16-bit PCM)
           │
           ▼
  ┌─────────────────────────────────────┐
  │  1. SERIALIZE audio samples         │
  │     16-bit big-endian integers      │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  2. BUILD ARSS HEADER (40 bytes)    │
  │     [ARSS magic: 4B]                │
  │     [payload length: 4B uint32]     │
  │     [SHA-256 checksum: 32B]         │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  3. CONVERT to bit stream           │
  │     Header bits + Payload bits      │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  4. LSB EMBED into pixel channels   │
  │     Replace N LSBs per R/G/B value  │
  │     Row-major order traversal       │
  └─────────────────────────────────────┘
           │
           ▼
OUTPUT: Stego-Image (PNG, lossless format preserves LSBs)
```

### Decoding Pipeline

```
INPUT: Stego-Image (PNG)
           │
           ▼
  ┌─────────────────────────────────────┐
  │  1. EXTRACT LSBs from pixel values  │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  2. PARSE HEADER                    │
  │     • Verify ARSS magic bytes       │
  │     • Read payload length           │
  │     • Read expected SHA-256 hash    │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  3. EXTRACT payload bits            │
  │     Reconstruct 16-bit samples      │
  └─────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────┐
  │  4. VERIFY SHA-256 checksum         │
  │     Detect tampering or corruption  │
  └─────────────────────────────────────┘
           │
           ▼
OUTPUT: Decoded Audio Samples + Verification Status
```

---

## 🔐 Security Properties

| Property | Mechanism | Benefit |
|:---|:---|:---|
| **Payload Integrity** | SHA-256 checksum in header | Detects any post-encoding tampering |
| **Magic Byte Marker** | `ARSS` 4-byte prefix | Confirms ARSS-encoded images; rejects others |
| **Imperceptibility** | LSB-only modification | PSNR > 40 dB — changes invisible to humans |
| **Configurable Depth** | 1–4 bits per channel | Balance between capacity and visual quality |
| **Lossless Output** | PNG format mandatory | JPEG compression destroys LSBs |

---

## 📊 Capacity Analysis

For an image of *W × H* pixels (RGB = 3 channels) using *n* bits per channel:

```
Capacity (bits) = W × H × 3 × n
Capacity (bytes) = W × H × 3 × n ÷ 8

Example — 512×512 image, 2 bits/channel:
  = 512 × 512 × 3 × 2 ÷ 8
  = 196,608 bytes ≈ 192 KB of audio payload
```

At 44,100 Hz, 16-bit mono audio: ~2.2 seconds of audio per MB.
A 512×512 image can hold ~0.4 seconds of uncompressed audio.
Larger or higher-resolution images increase capacity proportionally.

---

## 📂 File Structure

```
audio-steganography-arss/
├── arss_steg.py       # Core ARSS encode/decode engine (no external deps)
├── test_arss.py       # 20+ pytest unit tests
└── README.md          # This file
```

---

## 🚀 Quick Start

```bash
# Run all unit tests
pytest test_arss.py -v

# Use the library in Python
python3 - << 'EOF'
from arss_steg import encode_audio_in_image, decode_audio_from_image

# Synthetic "image" — in real use, load with Pillow and flatten pixels
cover_pixels = [(i * 37 + 128) % 256 for i in range(10000)]

# Synthetic "audio" — in real use, read a WAV file
audio_samples = [1000, 2000, 32000, 50000, 4096, 60000]

# Encode
result = encode_audio_in_image(cover_pixels, audio_samples)
print(f"PSNR: {result['psnr_db']} dB")
print(f"Utilization: {result['utilization_pct']}%")
print(f"Checksum: {result['checksum'][:32]}...")

# Decode
decoded = decode_audio_from_image(result['stego_pixels'])
print(f"Recovered {decoded['num_samples']} samples: {decoded['audio_samples']}")
print(f"Integrity verified: {decoded['checksum_verified']}")
EOF
```

---

## 🔬 Steganalysis Awareness

As a cybersecurity student, understanding *how to detect* steganography is equally important:

| Detection Method | What it finds |
|:---|:---|
| **Chi-square analysis** | Statistical anomalies in LSB distribution |
| **RS Analysis** | Detects regular/singular group patterns from LSB flipping |
| **Histogram comparison** | Luminance histogram differences between cover and stego |
| **File size anomalies** | Hidden data inflating file sizes unexpectedly |

The ARSS algorithm incorporates randomized bit distribution strategies (in a full implementation) to resist basic steganalysis, though advanced ML-based detectors remain a challenge.

---

## 📚 Academic References

- Johnson, N.F., & Jajodia, S. (1998). *Exploring Steganography: Seeing the Unseen.* IEEE Computer.
- Westfeld, A. (2001). *F5—A Steganographic Algorithm.* Lecture Notes in Computer Science.
- Fridrich, J. (2010). *Steganography in Digital Media: Principles, Algorithms and Applications.*
- NIST FIPS 180-4: Secure Hash Standard — SHA-256 specification.
