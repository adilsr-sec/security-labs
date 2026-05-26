"""
Unit Tests — ARSS Audio Steganography (Arjuna's Astra)
=======================================================
Tests cover:
  - Helper bit conversion functions
  - SHA-256 checksum computation
  - Header construction and parsing
  - Successful encode/decode round-trip
  - Payload integrity verification (tamper detection)
  - PSNR calculation (imperceptibility metric)
  - High-level API functions
  - Capacity overflow handling
  - Magic byte validation
"""

import struct
import pytest
from arss_steg import (
    ARSSEncoder,
    ARSS_MAGIC,
    BITS_PER_CHANNEL,
    HEADER_SIZE_BITS,
    _int_to_bits,
    _bits_to_int,
    _bytes_to_bits,
    _bits_to_bytes,
    compute_sha256,
    compute_psnr,
    encode_audio_in_image,
    decode_audio_from_image,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helper Function Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBitHelpers:
    def test_int_to_bits_zero(self):
        assert _int_to_bits(0, 8) == [0, 0, 0, 0, 0, 0, 0, 0]

    def test_int_to_bits_255(self):
        assert _int_to_bits(255, 8) == [1, 1, 1, 1, 1, 1, 1, 1]

    def test_int_to_bits_170(self):
        # 170 = 0b10101010
        assert _int_to_bits(170, 8) == [1, 0, 1, 0, 1, 0, 1, 0]

    def test_bits_to_int_roundtrip(self):
        for val in [0, 1, 42, 127, 255]:
            bits = _int_to_bits(val, 8)
            assert _bits_to_int(bits) == val

    def test_bytes_to_bits_length(self):
        data = b"\xAB\xCD"
        bits = _bytes_to_bits(data)
        assert len(bits) == 16

    def test_bits_to_bytes_roundtrip(self):
        original = b"ARSS"
        bits = _bytes_to_bits(original)
        recovered = _bits_to_bytes(bits)
        assert recovered == original


# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 / Checksum Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestChecksum:
    def test_sha256_is_32_bytes(self):
        digest = compute_sha256(b"test")
        assert len(digest) == 32

    def test_sha256_deterministic(self):
        assert compute_sha256(b"hello") == compute_sha256(b"hello")

    def test_sha256_different_inputs(self):
        assert compute_sha256(b"hello") != compute_sha256(b"world")


# ─────────────────────────────────────────────────────────────────────────────
# PSNR Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPSNR:
    def test_identical_images_returns_inf(self):
        pixels = [128] * 100
        assert compute_psnr(pixels, pixels) == float("inf")

    def test_small_lsb_change_high_psnr(self):
        """LSB steganography should yield PSNR > 40 dB."""
        original = [200, 100, 50, 180, 220] * 100
        # Flip only the LSB
        stego = [p ^ 1 for p in original]
        psnr = compute_psnr(original, stego)
        assert psnr > 40.0

    def test_large_change_low_psnr(self):
        """Large pixel modifications should yield lower PSNR."""
        original = [0] * 100
        stego = [128] * 100
        psnr = compute_psnr(original, stego)
        assert psnr < 30.0

    def test_mismatched_lengths_raises(self):
        with pytest.raises(ValueError):
            compute_psnr([1, 2, 3], [1, 2])


# ─────────────────────────────────────────────────────────────────────────────
# ARSSEncoder Header Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestARSSHeader:
    def setup_method(self):
        self.encoder = ARSSEncoder(bits_per_channel=2)

    def test_header_size(self):
        """Header must be exactly 40 bytes (320 bits)."""
        payload = b"test audio data"
        header = self.encoder._build_header(payload)
        assert len(header) == 40

    def test_header_starts_with_magic(self):
        payload = b"test"
        header = self.encoder._build_header(payload)
        assert header[:4] == ARSS_MAGIC

    def test_header_parse_roundtrip(self):
        payload = bytes(range(100))
        header = self.encoder._build_header(payload)
        payload_len, checksum = self.encoder._parse_header(header)
        assert payload_len == len(payload)
        assert checksum == compute_sha256(payload)

    def test_invalid_magic_raises(self):
        bad_header = b"XXXX" + b"\x00" * 36
        with pytest.raises(ValueError, match="Invalid magic bytes"):
            self.encoder._parse_header(bad_header)

    def test_short_header_raises(self):
        with pytest.raises(ValueError, match="Header too short"):
            self.encoder._parse_header(b"ARSS" + b"\x00" * 5)


# ─────────────────────────────────────────────────────────────────────────────
# Encode / Decode Round-Trip Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestARSSEncodeDecode:
    def _make_cover(self, n_channels: int = 10000) -> list[int]:
        """Create a synthetic cover pixel channel list."""
        # Varied pixel values simulating a real image
        return [(i * 37 + 128) % 256 for i in range(n_channels)]

    def test_small_payload_roundtrip(self):
        """Encode and decode a small audio sample set."""
        encoder = ARSSEncoder(bits_per_channel=2)
        samples = [1000, 2000, 30000, 60000, 500, 45000]
        cover = self._make_cover(5000)

        stego = encoder.encode(cover, samples)
        decoded = encoder.decode(stego)

        assert decoded == samples

    def test_larger_payload_roundtrip(self):
        """Encode and decode 100 audio samples."""
        encoder = ARSSEncoder(bits_per_channel=2)
        samples = [(i * 300) % 65536 for i in range(100)]
        cover = self._make_cover(50000)

        stego = encoder.encode(cover, samples)
        decoded = encoder.decode(stego)

        assert decoded == samples

    def test_different_bpc_roundtrip(self):
        """Round-trip works with different bits-per-channel settings."""
        for bpc in [1, 2, 3, 4]:
            encoder = ARSSEncoder(bits_per_channel=bpc)
            samples = [1234, 5678, 9012]
            cover = self._make_cover(20000)
            stego = encoder.encode(cover, samples)
            decoded = encoder.decode(stego)
            assert decoded == samples, f"Failed with bpc={bpc}"

    def test_stego_differs_from_cover(self):
        """Encoding should modify at least some pixels."""
        encoder = ARSSEncoder(bits_per_channel=2)
        samples = [32768, 16384, 49152]
        cover = self._make_cover(5000)
        stego = encoder.encode(cover, samples)
        assert cover != stego

    def test_payload_too_large_raises(self):
        """Encoding more than the capacity raises ValueError."""
        encoder = ARSSEncoder(bits_per_channel=1)
        tiny_cover = self._make_cover(50)  # Very small cover
        huge_samples = list(range(1000))   # Large payload
        with pytest.raises(ValueError, match="Payload too large"):
            encoder.encode(tiny_cover, huge_samples)

    def test_tampered_image_fails_checksum(self):
        """Flipping bits after encoding causes checksum failure."""
        encoder = ARSSEncoder(bits_per_channel=2)
        samples = [10000, 20000, 30000]
        cover = self._make_cover(5000)
        stego = encoder.encode(cover, samples)

        # Tamper with pixels after the header
        header_pixels = HEADER_SIZE_BITS // 2  # 2 bpc
        stego[header_pixels + 10] ^= 0b11   # Flip LSBs

        with pytest.raises(ValueError, match="Checksum mismatch"):
            encoder.decode(stego)

    def test_psnr_above_threshold(self):
        """Stego image PSNR should be > 40 dB (imperceptible changes)."""
        encoder = ARSSEncoder(bits_per_channel=2)
        samples = [5000, 10000, 20000, 40000]
        cover = self._make_cover(5000)
        stego = encoder.encode(cover, samples)

        psnr = compute_psnr(cover, stego)
        assert psnr > 40.0, f"PSNR {psnr} dB is too low — changes may be visible"

    def test_invalid_bpc_raises(self):
        with pytest.raises(ValueError):
            ARSSEncoder(bits_per_channel=0)
        with pytest.raises(ValueError):
            ARSSEncoder(bits_per_channel=5)


# ─────────────────────────────────────────────────────────────────────────────
# High-Level API Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHighLevelAPI:
    def test_encode_returns_stats(self):
        cover = [(i * 13) % 256 for i in range(10000)]
        samples = [1000, 2000, 3000]
        result = encode_audio_in_image(cover, samples)

        assert "stego_pixels" in result
        assert "psnr_db" in result
        assert "bits_embedded" in result
        assert "checksum" in result
        assert result["payload_samples"] == 3

    def test_decode_returns_verified_samples(self):
        cover = [(i * 17) % 256 for i in range(10000)]
        samples = [5000, 10000, 50000]
        encode_result = encode_audio_in_image(cover, samples)

        decode_result = decode_audio_from_image(encode_result["stego_pixels"])
        assert decode_result["audio_samples"] == samples
        assert decode_result["checksum_verified"] is True

    def test_checksums_match(self):
        cover = [(i * 19) % 256 for i in range(10000)]
        samples = [100, 200, 300, 400]
        enc = encode_audio_in_image(cover, samples)
        dec = decode_audio_from_image(enc["stego_pixels"])
        assert enc["checksum"] == dec["checksum"]
