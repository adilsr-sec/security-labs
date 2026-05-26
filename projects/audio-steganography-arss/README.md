# Audio in Image Steganography Using ARSS Algorithm (Arjuna's Astra)

An academic research project implementing a secure data-hiding utility that embeds audio payload files inside cover image containers using the **Adaptive Randomized Spatial Substitution (ARSS) Algorithm (codename: Arjuna's Astra)**.

---

## 🎯 Project Objective

Steganography is the practice of concealing a file, message, image, or video within another file. The main objective of this project was to:
1. Hide high-fidelity audio signals (WAV format) inside digital images (PNG format).
2. Avoid visual artifacts or distortion that could tip off human observers or automated steganalysis engines.
3. Design a custom selection method (**ARSS / Arjuna's Astra**) that increases encryption key-space complexity and secures the data payload.

---

## 🧬 The ARSS Algorithm (Arjuna's Astra)

Traditional Least Significant Bit (LSB) steganography replaces sequential bit arrays, making it highly vulnerable to **Chi-Square Statistical Steganalysis**. 

**Arjuna's Astra** mitigates this through two primary components:

```text
       +--------------------+
       |  WAV Audio Payload |
       +---------+----------+
                 | (Compress & Encrypt)
                 v
       +--------------------+
       | Bitstream Packet   |
       +---------+----------+
                 |
                 v     +--------------------+
                 +---->| ARSS Selector      |<---+ Secret Key Seed
                       +---------+----------+
                                 | (Adaptive Spatial Embedding)
                                 v
                       +--------------------+
                       | Cover Image (PNG)  |
                       +---------+----------+
                                 |
                                 v
                       +--------------------+
                       | Stego-Image File   |
                       +--------------------+
```

### 1. Adaptive Bit-Depth Embedding
Instead of hiding a fixed number of bits per pixel, the algorithm measures **local pixel variance** (neighborhood texture). 
* **High-texture regions** (busy patterns, edges) can tolerate higher bit-depth changes (up to 3 bits/pixel) without human detection.
* **Low-texture regions** (flat gradients, skies) are restricted to 0 or 1 bit/pixel.

### 2. Randomized Spatial Distribution
* The algorithm uses a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) seeded with a **shared secret key**.
* This seed determines the traversal order of coordinates across the cover image. 
* Without the secret key, an attacker cannot identify which pixels contain payload bits, even if they suspect steganography is being used.

---

## 🔄 Lifecycle Workflow

### Embedding Phase
1. **Payload Pre-processing:** The input `.wav` audio file is compressed (removing headers where possible) and encrypted using a lightweight symmetric cipher.
2. **Texture Analysis:** The cover image `.png` is analyzed block-by-block to map texture thresholds.
3. **CSPRNG Seeding:** The secret key seeds the coordinate picker.
4. **Adaptive Substitution:** Bits are packed into selected pixel color channels according to local threshold capacities.
5. **Output Generation:** The output `.png` (stego-image) is saved losslessly.

### Extraction Phase
1. **Coordinate Retrieval:** The recipient inputs the same secret key, reproducing the exact randomized coordinate map.
2. **Bit Extraction:** Read color channel LSB structures matching the texture map.
3. **Reassembly:** Decrypt and decompress the bitstream to reconstruct the original functional `.wav` audio.

---

## 📈 Security Evaluation Metrics

To prove the efficacy of the Arjuna's Astra algorithm, the outputs were tested against standard benchmarks:

* **Peak Signal-to-Noise Ratio (PSNR):** Measures logarithmic ratio between the maximum possible power of a signal and the corrupting noise.
  - *Result:* **> 45 dB** (Values above 30 dB are considered imperceptible to the human eye).
* **Structural Similarity Index (SSIM):** Evaluates luminance, contrast, and structure similarity.
  - *Result:* **0.998** (Where 1.0 represents a perfect identical image match).
* **Statistical Resistance:** Tested against Chi-Square analysis. The randomized coordinate distribution prevents the expected clustering of bit patterns, resisting standard detection scans.
