#!/usr/bin/env python3
"""
Audio-in-Image Steganography — ARSS Algorithm (Arjuna's Astra)
================================================================
Academic Project — Cybersecurity Engineering Portfolio

ARSS: Arjuna's Astra Robust Steganography Scheme
  A custom steganography algorithm that encodes audio waveform data
  (amplitude samples) into the Least-Significant Bits (LSBs) of a
  cover image's pixel channels.

Algorithm Overview:
  ENCODE:
    1. Read audio file, extract samples as 16-bit integers.
    2. Normalize samples to [0, 65535] range.
    3. Serialize sample stream to a binary bit-string.
    4. Prepend a header: [magic_bytes(16)] [payload_length(32)] [checksum(32)]
    5. Embed bits into cover image pixels: R→G→B channels, row-major order.
    6. Each pixel channel's LSBs (configurable 1–4 bits) are replaced.
    7. Output stego-image (PNG to prevent lossy compression).

  DECODE:
    1. Read stego-image, extract LSBs from pixel channels.
    2. Parse header: verify magic bytes, read payload length, read checksum.
    3. Extract payload bits, reconstruct 16-bit audio samples.
    4. Verify SHA-256 checksum for integrity.
    5. Write decoded audio to output file.

Security Features:
  - SHA-256 payload checksum: detects corrupted or tampered stego-images.
  - Magic byte header: confirms this image was encoded with ARSS.
  - PSNR measurement: quantifies visual imperceptibility.
  - Capacity check: refuses to encode payload exceeding image capacity.

Author: Adil S R
Course: Steganography & Digital Watermarking (Academic Project)
"""

import hashlib
import struct
import sys
import os
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

ARSS_MAGIC = b"ARSS"          # 4-byte magic marker
BITS_PER_CHANNEL = 2          # LSBs to use per color channel (1-4)
HEADER_SIZE_BITS = (
    len(ARSS_MAGIC) * 8       # 32 bits magic
    + 32                       # 32 bits payload length
    + 256                      # 256 bits SHA-256 checksum
)  # Total: 320 bits header


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _int_to_bits(value: int, num_bits: int) -> list[int]:
    """Convert an integer to a list of bits (MSB first)."""
    return [(value >> (num_bits - 1 - i)) & 1 for i in range(num_bits)]


def _bits_to_int(bits: list[int]) -> int:
    """Convert a list of bits (MSB first) to an integer."""
    result = 0
    for bit in bits:
        result = (result << 1) | bit
    return result


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a flat list of bits."""
    bits = []
    for byte in data:
        bits.extend(_int_to_bits(byte, 8))
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a flat list of bits (must be multiple of 8) to bytes."""
    assert len(bits) % 8 == 0, "Bit count must be a multiple of 8"
    return bytes(_bits_to_int(bits[i:i+8]) for i in range(0, len(bits), 8))


def compute_sha256(data: bytes) -> bytes:
    """Return 32-byte SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


# ─────────────────────────────────────────────────────────────────────────────
# PSNR (Peak Signal-to-Noise Ratio) — Imperceptibility Metric
# ─────────────────────────────────────────────────────────────────────────────

def compute_psnr(original_pixels: list, stego_pixels: list) -> float:
    """
    Compute PSNR between original and stego images.

    PSNR > 40 dB: changes are imperceptible to the human eye.
    PSNR > 30 dB: minor visible noise may appear.

    Args:
        original_pixels: Flat list of original pixel channel values.
        stego_pixels:    Flat list of stego pixel channel values.

    Returns:
        PSNR in decibels (dB), or float('inf') if images are identical.
    """
    if len(original_pixels) != len(stego_pixels):
        raise ValueError("Pixel lists must be the same length.")

    mse = sum(
        (o - s) ** 2 for o, s in zip(original_pixels, stego_pixels)
    ) / len(original_pixels)

    if mse == 0:
        return float("inf")

    max_pixel_value = 255.0
    import math
    psnr = 10 * math.log10((max_pixel_value ** 2) / mse)
    return round(psnr, 2)


# ─────────────────────────────────────────────────────────────────────────────
# Core ARSS Encoder / Decoder (image-independent core)
# ─────────────────────────────────────────────────────────────────────────────

class ARSSEncoder:
    """
    ARSS (Arjuna's Astra Robust Steganography Scheme) encoder.

    Embeds an audio payload into pixel data using LSB substitution
    with header integrity verification.

    The encoder works on raw pixel data (flat list of 0-255 integers)
    so it can be used with any image library (Pillow, OpenCV, etc.).
    For demonstration purposes without external dependencies, this module
    operates on synthetic pixel arrays and provides the core algorithm.
    """

    def __init__(self, bits_per_channel: int = BITS_PER_CHANNEL):
        if not 1 <= bits_per_channel <= 4:
            raise ValueError("bits_per_channel must be between 1 and 4.")
        self.bpc = bits_per_channel

    def _build_header(self, payload_bytes: bytes) -> bytes:
        """
        Construct the ARSS header:
          [magic: 4B] [payload_len: 4B uint32] [sha256: 32B]
        Total: 40 bytes = 320 bits
        """
        magic = ARSS_MAGIC
        payload_len = struct.pack(">I", len(payload_bytes))
        checksum = compute_sha256(payload_bytes)
        return magic + payload_len + checksum

    def _parse_header(self, header_bytes: bytes) -> tuple[int, bytes]:
        """
        Parse the 40-byte ARSS header.

        Returns:
            (payload_length, expected_sha256_checksum)

        Raises:
            ValueError: If magic bytes are invalid.
        """
        if len(header_bytes) < 40:
            raise ValueError("Header too short — not an ARSS stego-image.")

        magic = header_bytes[:4]
        if magic != ARSS_MAGIC:
            raise ValueError(
                f"Invalid magic bytes {magic!r}. "
                "This image was not encoded with ARSS."
            )
        payload_len = struct.unpack(">I", header_bytes[4:8])[0]
        checksum = header_bytes[8:40]
        return payload_len, checksum

    def encode(
        self,
        cover_pixels: list[int],
        audio_samples: list[int],
        sample_rate: int = 44100,
    ) -> list[int]:
        """
        Encode audio samples into cover image pixels using ARSS.

        Args:
            cover_pixels:  Flat list of pixel channel values (R,G,B,...).
            audio_samples: List of 16-bit audio sample values (0-65535).
            sample_rate:   Audio sample rate in Hz (stored in metadata).

        Returns:
            Modified pixel list with embedded payload.

        Raises:
            ValueError: If payload is too large for the cover image.
        """
        # Serialize audio samples as big-endian 16-bit integers
        payload_bytes = struct.pack(f">{len(audio_samples)}H", *audio_samples)
        header_bytes = self._build_header(payload_bytes)

        # Full bitstream = header bits + payload bits
        all_bits = _bytes_to_bits(header_bytes + payload_bytes)

        # Capacity check
        capacity = len(cover_pixels) * self.bpc
        if len(all_bits) > capacity:
            raise ValueError(
                f"Payload too large: need {len(all_bits)} bits, "
                f"but image capacity is {capacity} bits. "
                f"Use a larger cover image or fewer audio samples."
            )

        stego_pixels = list(cover_pixels)
        bit_idx = 0
        mask = (1 << self.bpc) - 1  # e.g., 0b11 for bpc=2

        for px_idx in range(len(stego_pixels)):
            if bit_idx >= len(all_bits):
                break
            # Extract `bpc` bits from the stream
            chunk_bits = all_bits[bit_idx : bit_idx + self.bpc]
            # Pad if at the end
            while len(chunk_bits) < self.bpc:
                chunk_bits.append(0)

            chunk_val = _bits_to_int(chunk_bits)
            # Replace the LSBs of this pixel channel
            stego_pixels[px_idx] = (cover_pixels[px_idx] & ~mask) | chunk_val
            bit_idx += self.bpc

        return stego_pixels

    def decode(self, stego_pixels: list[int]) -> list[int]:
        """
        Decode audio samples from a stego-image's pixel data.

        Args:
            stego_pixels: Flat list of pixel channel values from stego-image.

        Returns:
            List of 16-bit audio sample integers.

        Raises:
            ValueError: For invalid magic bytes or checksum mismatch.
        """
        mask = (1 << self.bpc) - 1

        # Extract all LSB bits
        extracted_bits: list[int] = []
        for px_val in stego_pixels:
            chunk_val = px_val & mask
            extracted_bits.extend(_int_to_bits(chunk_val, self.bpc))

        # Parse header (first 320 bits = 40 bytes)
        header_bytes = _bits_to_bytes(extracted_bits[:HEADER_SIZE_BITS])
        payload_len, expected_checksum = self._parse_header(header_bytes)

        # Extract payload
        payload_start = HEADER_SIZE_BITS
        payload_bits_needed = payload_len * 8
        payload_bits = extracted_bits[payload_start : payload_start + payload_bits_needed]

        if len(payload_bits) < payload_bits_needed:
            raise ValueError("Extracted bits are insufficient — image may be corrupted.")

        payload_bytes = _bits_to_bytes(payload_bits)

        # Verify checksum
        actual_checksum = compute_sha256(payload_bytes)
        if actual_checksum != expected_checksum:
            raise ValueError(
                "Checksum mismatch! The stego-image may have been tampered with "
                "or corrupted during transmission."
            )

        # Deserialize audio samples
        num_samples = payload_len // 2  # Each sample is 2 bytes (uint16)
        audio_samples = list(struct.unpack(f">{num_samples}H", payload_bytes))
        return audio_samples


# ─────────────────────────────────────────────────────────────────────────────
# High-level API
# ─────────────────────────────────────────────────────────────────────────────

def encode_audio_in_image(
    cover_pixels: list[int],
    audio_samples: list[int],
    bits_per_channel: int = BITS_PER_CHANNEL,
) -> dict:
    """
    High-level encoding function.

    Args:
        cover_pixels:     Flat pixel channel values for the cover image.
        audio_samples:    16-bit audio samples to embed.
        bits_per_channel: LSBs to use per channel (1-4).

    Returns:
        Dictionary with stego_pixels, psnr, and embedding stats.
    """
    encoder = ARSSEncoder(bits_per_channel)
    stego_pixels = encoder.encode(cover_pixels, audio_samples)
    psnr = compute_psnr(cover_pixels, stego_pixels)

    payload_bytes = struct.pack(f">{len(audio_samples)}H", *audio_samples)
    header_bytes = encoder._build_header(payload_bytes)
    total_bits = len(_bytes_to_bits(header_bytes + payload_bytes))
    capacity = len(cover_pixels) * bits_per_channel

    return {
        "stego_pixels": stego_pixels,
        "psnr_db": psnr,
        "payload_samples": len(audio_samples),
        "payload_bytes": len(payload_bytes),
        "bits_embedded": total_bits,
        "capacity_bits": capacity,
        "utilization_pct": round(total_bits / capacity * 100, 2),
        "bits_per_channel": bits_per_channel,
        "checksum": compute_sha256(payload_bytes).hex(),
    }


def decode_audio_from_image(
    stego_pixels: list[int],
    bits_per_channel: int = BITS_PER_CHANNEL,
) -> dict:
    """
    High-level decoding function.

    Args:
        stego_pixels:     Pixel values from the stego-image.
        bits_per_channel: LSBs per channel used during encoding.

    Returns:
        Dictionary with audio_samples and verification status.
    """
    encoder = ARSSEncoder(bits_per_channel)
    audio_samples = encoder.decode(stego_pixels)

    payload_bytes = struct.pack(f">{len(audio_samples)}H", *audio_samples)
    checksum = compute_sha256(payload_bytes).hex()

    return {
        "audio_samples": audio_samples,
        "num_samples": len(audio_samples),
        "checksum_verified": True,
        "checksum": checksum,
    }
