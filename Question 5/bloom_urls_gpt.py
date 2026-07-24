#!/usr/bin/env python3
"""
Standard-library-only Bloom filter for URL datasets.

Expected input:
  - malicious_urls.txt: one cleaned, already-unique URL per line
  - non_malicious_urls.txt: one cleaned, already-unique URL per line

The Bloom filter is built only from malicious URLs.

Exact Python sets are used only for:
  - verifying false negatives
  - detecting dataset overlaps
  - excluding overlaps from Bloom false-positive counts

Usage:
  python3 bloom_urls.py \
    --malicious malicious_urls.txt \
    --non-malicious non_malicious_urls.txt \
    --fp-rate 0.01
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
import time
from pathlib import Path
from typing import Iterator


class BloomFilter:
    """
    Memory-efficient Bloom filter using:
      - bytearray-backed bit storage
      - deterministic SHA-256 double hashing
      - no use of Python's hash()
    """

    def __init__(self, expected_items: int, target_fp_rate: float) -> None:
        if expected_items < 0:
            raise ValueError("expected_items must be non-negative")
        if not (0.0 < target_fp_rate < 1.0):
            raise ValueError("target_fp_rate must be between 0 and 1")

        self.expected_items = expected_items
        self.target_fp_rate = target_fp_rate

        if expected_items == 0:
            self.num_bits = 8
            self.num_hashes = 1
        else:
            # m = -n ln(p) / (ln 2)^2
            self.num_bits = max(
                8,
                math.ceil(
                    -expected_items * math.log(target_fp_rate)
                    / (math.log(2) ** 2)
                ),
            )

            # k = (m / n) ln 2
            self.num_hashes = max(
                1,
                round((self.num_bits / expected_items) * math.log(2)),
            )

        self.num_bytes = (self.num_bits + 7) // 8
        self.bits = bytearray(self.num_bytes)

    def _hashes(self, url: str) -> Iterator[int]:
        """
        Generate k Bloom-filter positions using SHA-256 double hashing.

        SHA-256 gives 256 bits. We split the digest into two deterministic
        128-bit integers h1 and h2, then generate:

            position_i = (h1 + i * h2) mod m

        This avoids calling hashlib k separate times per URL.
        """
        data = url.encode("utf-8")
        digest = hashlib.sha256(data).digest()

        h1 = int.from_bytes(digest[:16], "big")
        h2 = int.from_bytes(digest[16:], "big")

        # Extremely unlikely, but avoid a zero step size.
        if h2 == 0:
            h2 = 0x9E3779B97F4A7C15

        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.num_bits

    def add(self, url: str) -> None:
        for pos in self._hashes(url):
            byte_index = pos >> 3
            bit_mask = 1 << (pos & 7)
            self.bits[byte_index] |= bit_mask

    def might_contain(self, url: str) -> bool:
        for pos in self._hashes(url):
            byte_index = pos >> 3
            bit_mask = 1 << (pos & 7)
            if not (self.bits[byte_index] & bit_mask):
                return False
        return True


def iter_urls(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="strict") as f:
        for line in f:
            url = line.rstrip("\n\r")
            if url:
                yield url


def count_urls(path: Path, progress_every: int) -> int:
    count = 0
    last_report = 0

    with path.open("r", encoding="utf-8", errors="strict") as f:
        for line in f:
            if line.rstrip("\n\r"):
                count += 1

            if progress_every and count - last_report >= progress_every:
                print(
                    f"[progress] counted {count:,} URLs in {path.name}",
                    file=sys.stderr,
                )
                last_report = count

    return count


def load_exact_set(path: Path, progress_every: int, label: str) -> set[str]:
    exact: set[str] = set()
    last_report = 0

    for url in iter_urls(path):
        exact.add(url)

        if progress_every and len(exact) - last_report >= progress_every:
            print(
                f"[progress] loaded {len(exact):,} {label} URLs into exact set",
                file=sys.stderr,
            )
            last_report = len(exact)

    return exact


def insert_urls(
    bloom: BloomFilter,
    path: Path,
    total: int,
    progress_every: int,
) -> int:
    inserted = 0
    last_report = 0

    for url in iter_urls(path):
        bloom.add(url)
        inserted += 1

        if progress_every and inserted - last_report >= progress_every:
            pct = (inserted / total * 100.0) if total else 100.0
            print(
                f"[progress] inserted {inserted:,}/{total:,} malicious URLs "
                f"({pct:.2f}%)",
                file=sys.stderr,
            )
            last_report = inserted

    return inserted


def verify_false_negatives(
    bloom: BloomFilter,
    malicious_exact: set[str],
    progress_every: int,
) -> int:
    false_negatives = 0
    checked = 0
    total = len(malicious_exact)
    last_report = 0

    for url in malicious_exact:
        if not bloom.might_contain(url):
            false_negatives += 1

        checked += 1

        if progress_every and checked - last_report >= progress_every:
            pct = (checked / total * 100.0) if total else 100.0
            print(
                f"[progress] checked {checked:,}/{total:,} malicious URLs "
                f"for false negatives ({pct:.2f}%)",
                file=sys.stderr,
            )
            last_report = checked

    return false_negatives


def measure_false_positives(
    bloom: BloomFilter,
    non_malicious_exact: set[str],
    overlaps: set[str],
    progress_every: int,
) -> tuple[int, int]:
    false_positives = 0
    tested = 0
    seen = 0
    total = len(non_malicious_exact)
    last_report = 0

    for url in non_malicious_exact:
        seen += 1

        # Overlaps are actually present in the malicious dataset, so a Bloom
        # "hit" for them is not a false positive.
        if url in overlaps:
            continue

        tested += 1
        if bloom.might_contain(url):
            false_positives += 1

        if progress_every and seen - last_report >= progress_every:
            pct = (seen / total * 100.0) if total else 100.0
            print(
                f"[progress] scanned {seen:,}/{total:,} non-malicious URLs; "
                f"tested {tested:,} after excluding overlaps",
                file=sys.stderr,
            )
            last_report = seen

    return false_positives, tested


def human_bytes(num_bytes: int) -> str:
    value = float(num_bytes)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]

    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0

    return f"{num_bytes} B"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and evaluate a SHA-256 Bloom filter for URL datasets."
    )
    parser.add_argument(
        "--malicious",
        type=Path,
        default=Path("malicious_urls.txt"),
        help="Path to malicious URL file.",
    )
    parser.add_argument(
        "--non-malicious",
        type=Path,
        default=Path("non_malicious_urls.txt"),
        help="Path to non-malicious URL file.",
    )
    parser.add_argument(
        "--fp-rate",
        type=float,
        default=0.01,
        help="Target Bloom false-positive rate, e.g. 0.01 for 1%%.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100_000,
        help="Print progress every N URLs. Use 0 to disable progress.",
    )

    args = parser.parse_args()

    malicious_path = args.malicious
    non_malicious_path = args.non_malicious
    target_fp_rate = args.fp_rate
    progress_every = args.progress_every

    if not malicious_path.exists():
        raise FileNotFoundError(malicious_path)
    if not non_malicious_path.exists():
        raise FileNotFoundError(non_malicious_path)

    overall_start = time.perf_counter()

    print("=== Bloom filter URL evaluation ===")
    print(f"Malicious file:      {malicious_path}")
    print(f"Non-malicious file:  {non_malicious_path}")
    print(f"Target FP rate:      {target_fp_rate:.8f}")
    print()

    print("Counting malicious URLs for Bloom sizing...")
    t0 = time.perf_counter()
    malicious_count = count_urls(malicious_path, progress_every)
    count_time = time.perf_counter() - t0

    bloom = BloomFilter(
        expected_items=malicious_count,
        target_fp_rate=target_fp_rate,
    )

    print()
    print("Bloom configuration:")
    print(f"  Expected inserted items: {bloom.expected_items:,}")
    print(f"  Bit array size:          {bloom.num_bits:,} bits")
    print(f"  Backing bytearray size:  {bloom.num_bytes:,} bytes")
    print(f"  Backing bytearray size:  {human_bytes(bloom.num_bytes)}")
    print(f"  Number of hash probes:   {bloom.num_hashes}")
    print()

    print("Inserting malicious URLs into Bloom filter...")
    t0 = time.perf_counter()
    inserted = insert_urls(
        bloom=bloom,
        path=malicious_path,
        total=malicious_count,
        progress_every=progress_every,
    )
    insertion_time = time.perf_counter() - t0

    print("Loading exact sets for verification and overlap detection...")
    t0 = time.perf_counter()
    malicious_exact = load_exact_set(
        malicious_path,
        progress_every,
        "malicious",
    )
    non_malicious_exact = load_exact_set(
        non_malicious_path,
        progress_every,
        "non-malicious",
    )
    exact_load_time = time.perf_counter() - t0

    print("Detecting overlaps...")
    t0 = time.perf_counter()
    overlaps = malicious_exact & non_malicious_exact
    overlap_time = time.perf_counter() - t0

    print("Checking malicious URLs for Bloom false negatives...")
    t0 = time.perf_counter()
    false_negatives = verify_false_negatives(
        bloom,
        malicious_exact,
        progress_every,
    )
    false_negative_query_time = time.perf_counter() - t0

    print("Checking non-malicious URLs for Bloom false positives...")
    t0 = time.perf_counter()
    bloom_false_positives, non_overlap_tested = measure_false_positives(
        bloom,
        non_malicious_exact,
        overlaps,
        progress_every,
    )
    false_positive_query_time = time.perf_counter() - t0

    measured_fp_rate = (
        bloom_false_positives / non_overlap_tested
        if non_overlap_tested
        else 0.0
    )

    total_time = time.perf_counter() - overall_start

    print()
    print("=== Results ===")
    print(f"Malicious URLs counted:              {malicious_count:,}")
    print(f"Malicious URLs inserted:             {inserted:,}")
    print(f"Malicious exact-set size:            {len(malicious_exact):,}")
    print(f"Non-malicious exact-set size:        {len(non_malicious_exact):,}")
    print(f"Dataset overlaps:                    {len(overlaps):,}")
    print(f"Non-malicious tested after overlaps: {non_overlap_tested:,}")
    print(f"Bloom false negatives:               {false_negatives:,}")
    print(f"Bloom false positives:               {bloom_false_positives:,}")
    print(f"Measured FP rate:                    {measured_fp_rate:.8f}")
    print()

    print("=== Timing ===")
    print(f"Counting time:                       {count_time:.4f} seconds")
    print(f"Insertion time:                      {insertion_time:.4f} seconds")
    print(
        f"Insertion throughput:                "
        f"{inserted / insertion_time:,.2f} URLs/sec"
        if insertion_time > 0
        else "Insertion throughput:                n/a"
    )
    print(f"Exact-set load time:                 {exact_load_time:.4f} seconds")
    print(f"Overlap detection time:              {overlap_time:.4f} seconds")
    print(
        f"False-negative query time:           "
        f"{false_negative_query_time:.4f} seconds"
    )
    print(
        f"False-negative query throughput:     "
        f"{len(malicious_exact) / false_negative_query_time:,.2f} URLs/sec"
        if false_negative_query_time > 0
        else "False-negative query throughput:     n/a"
    )
    print(
        f"False-positive query time:           "
        f"{false_positive_query_time:.4f} seconds"
    )
    print(
        f"False-positive query throughput:     "
        f"{non_overlap_tested / false_positive_query_time:,.2f} URLs/sec"
        if false_positive_query_time > 0
        else "False-positive query throughput:     n/a"
    )
    print(f"Total runtime:                       {total_time:.4f} seconds")
    print()

    print("=== Explanation ===")
    print(
        "Hashing: each URL is encoded as UTF-8 and hashed once with SHA-256. "
        "The 256-bit digest is split into two 128-bit integers, h1 and h2. "
        "The Bloom filter uses double hashing, generating positions as "
        "(h1 + i * h2) mod m for i from 0 to k-1. This is deterministic and "
        "does not use Python's randomized hash()."
    )
    print(
        "Performance: insertion and membership checks both cost O(k) bit probes "
        "per URL. The bytearray stores only the Bloom bit array, so Bloom memory "
        "usage is roughly m / 8 bytes. Exact sets are intentionally separate and "
        "are used only for validation, overlap detection, and fair false-positive "
        "measurement."
    )
    print(
        "False positives: URLs present in both files are excluded from the "
        "false-positive denominator and numerator, because a Bloom hit for an "
        "overlapping URL is expected after inserting the malicious dataset."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())