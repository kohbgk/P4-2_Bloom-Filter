#!/usr/bin/env python3
"""
Bloom filter for URL blocklists — standard library only.

Builds a memory-efficient Bloom filter over the URLs in `malicious_urls.txt`,
then evaluates it against `non_malicious_urls.txt`.

Design highlights
-----------------
* Bit storage is a raw ``bytearray`` (1 bit per slot, 8 slots per byte).
* Hashing is deterministic SHA-256 double hashing (Kirsch-Mitzenmacher):
  a single SHA-256 digest is split into two 128-bit integers h1, h2 and the
  k probe positions are  g_i(x) = (h1 + i * h2) mod m.  Python's built-in
  ``hash()`` is never used, so results are stable across runs/processes.
* Filter size m and hash count k are derived from a configurable target
  false-positive rate and the number of items inserted.

Evaluation methodology
-----------------------
* Exact Python ``set`` objects hold ground truth.
* False negatives: every malicious URL is queried; a Bloom filter must return
  True for all of them (they cannot produce false negatives by construction),
  so any miss indicates a bug or data corruption.
* Overlap: URLs present in *both* files are true members of the malicious set,
  so a "hit" on them is a true positive, not a false positive. Overlaps are
  detected via set intersection and excluded from the FP denominator/count.
* False positives: non-malicious URLs that are NOT in the malicious set but for
  which ``might_contain`` returns True.
"""

import hashlib
import math
import os
import sys
import time

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
TARGET_FP_RATE = 0.01          # configurable target false-positive probability
MALICIOUS_FILE = "malicious_urls.txt"
NONMALICIOUS_FILE = "non_malicious_urls.txt"


# ----------------------------------------------------------------------------
# Bloom filter
# ----------------------------------------------------------------------------
class BloomFilter:
    """Bit-packed Bloom filter using SHA-256 double hashing."""

    def __init__(self, expected_items: int, target_fp_rate: float):
        if not 0.0 < target_fp_rate < 1.0:
            raise ValueError("target_fp_rate must be in (0, 1)")
        n = max(1, expected_items)  # avoid degenerate sizing when file is empty

        # Optimal number of bits:   m = -n * ln(p) / (ln 2)^2
        # Optimal number of hashes: k = (m / n) * ln 2
        ln2 = math.log(2.0)
        m = math.ceil(-(n * math.log(target_fp_rate)) / (ln2 * ln2))
        k = max(1, round((m / n) * ln2))

        self.expected_items = n
        self.target_fp_rate = target_fp_rate
        self.m = m                      # number of bit slots
        self.k = k                      # number of hash functions
        self.num_bytes = (m + 7) // 8   # ceil(m / 8)
        self.bits = bytearray(self.num_bytes)
        self.count = 0                  # items actually inserted

    # --- hashing -----------------------------------------------------------
    def _indices(self, url: str):
        """Yield the k bit positions for ``url`` via SHA-256 double hashing."""
        digest = hashlib.sha256(url.encode("utf-8")).digest()  # 32 bytes
        h1 = int.from_bytes(digest[:16], "big")                # low 128 bits
        h2 = int.from_bytes(digest[16:], "big") | 1            # high 128 bits, forced odd/nonzero
        m = self.m
        idx = h1 % m
        step = h2 % m
        for _ in range(self.k):
            yield idx
            idx = (idx + step) % m

    # --- API ---------------------------------------------------------------
    def add(self, url: str) -> None:
        bits = self.bits
        for idx in self._indices(url):
            bits[idx >> 3] |= (1 << (idx & 7))
        self.count += 1

    def might_contain(self, url: str) -> bool:
        bits = self.bits
        for idx in self._indices(url):
            if not (bits[idx >> 3] >> (idx & 7)) & 1:
                return False   # a clear bit proves absence
        return True            # all bits set -> probably present

    # --- diagnostics -------------------------------------------------------
    def bits_set(self) -> int:
        return sum(bin(b).count("1") for b in self.bits)

    def theoretical_fp_rate(self) -> float:
        # (1 - e^(-k n / m))^k  using the actual inserted count
        n = self.count or self.expected_items
        return (1.0 - math.exp(-self.k * n / self.m)) ** self.k


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def human_bytes(num: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if num < 1024 or unit == "GiB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024.0


def load_urls(path: str) -> list:
    """Read one URL per line; strip whitespace, drop blank lines."""
    urls = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            u = line.strip()
            if u:
                urls.append(u)
    return urls


def progress(prefix: str, done: int, total: int, every: int) -> None:
    if total and (done % every == 0 or done == total):
        pct = 100.0 * done / total
        sys.stdout.write(f"\r  {prefix}: {done:,}/{total:,} ({pct:5.1f}%)")
        sys.stdout.flush()
        if done == total:
            sys.stdout.write("\n")


def generate_demo_data() -> None:
    """Create small synthetic files so the script is runnable without inputs."""
    print("Input files not found -> generating synthetic demo data.\n")
    n_mal, n_clean, n_overlap = 20000, 20000, 200
    with open(MALICIOUS_FILE, "w", encoding="utf-8") as fh:
        for i in range(n_mal):
            fh.write(f"http://malware-{i}.example.net/path/{i*7 % 999}\n")
    with open(NONMALICIOUS_FILE, "w", encoding="utf-8") as fh:
        # first n_overlap lines intentionally duplicate malicious URLs
        for i in range(n_overlap):
            fh.write(f"http://malware-{i}.example.net/path/{i*7 % 999}\n")
        for i in range(n_clean):
            fh.write(f"https://safe-{i}.example.org/page?id={i*3 % 1234}\n")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main() -> None:
    if not (os.path.exists(MALICIOUS_FILE) and os.path.exists(NONMALICIOUS_FILE)):
        generate_demo_data()

    print("Loading input files ...")
    malicious = load_urls(MALICIOUS_FILE)
    non_malicious = load_urls(NONMALICIOUS_FILE)
    print(f"  malicious URLs     : {len(malicious):,}")
    print(f"  non-malicious URLs : {len(non_malicious):,}\n")

    # Exact ground-truth sets.
    mal_set = set(malicious)
    clean_set = set(non_malicious)

    # Build the filter, sized from the target FP rate and the malicious count.
    bf = BloomFilter(expected_items=len(mal_set), target_fp_rate=TARGET_FP_RATE)
    print("Bloom filter parameters")
    print(f"  target FP rate     : {TARGET_FP_RATE:.4%}")
    print(f"  bit slots (m)      : {bf.m:,}")
    print(f"  hash functions (k) : {bf.k}")
    print(f"  memory             : {human_bytes(bf.num_bytes)}\n")

    # --- insertion --------------------------------------------------------
    print("Inserting malicious URLs ...")
    every_ins = max(1, len(malicious) // 20)
    t0 = time.perf_counter()
    for i, url in enumerate(malicious, 1):
        bf.add(url)
        progress("insert", i, len(malicious), every_ins)
    insert_time = time.perf_counter() - t0
    ins_rate = len(malicious) / insert_time if insert_time else float("inf")
    print(f"  inserted {bf.count:,} URLs in {insert_time:.3f}s "
          f"({ins_rate:,.0f} URLs/s)")
    print(f"  bits set           : {bf.bits_set():,}/{bf.m:,} "
          f"({bf.bits_set()/bf.m:.1%})\n")

    # --- false-negative check --------------------------------------------
    print("Verifying no false negatives (querying every malicious URL) ...")
    every_fn = max(1, len(malicious) // 20)
    false_negatives = 0
    t0 = time.perf_counter()
    for i, url in enumerate(malicious, 1):
        if not bf.might_contain(url):
            false_negatives += 1
        progress("verify", i, len(malicious), every_fn)
    fn_time = time.perf_counter() - t0
    print(f"  completed in {fn_time:.3f}s\n")

    # --- overlap detection ------------------------------------------------
    overlap = mal_set & clean_set
    print(f"Dataset overlap (URLs in BOTH files): {len(overlap):,}")
    if overlap:
        for u in list(sorted(overlap))[:3]:
            print(f"    e.g. {u}")
    print()

    # --- false-positive measurement --------------------------------------
    print("Querying non-malicious URLs for false positives ...")
    every_fp = max(1, len(non_malicious) // 20)
    false_positives = 0
    tested = 0            # non-malicious, non-overlapping URLs actually tested
    t0 = time.perf_counter()
    for i, url in enumerate(non_malicious, 1):
        if url in mal_set:
            # true member -> a hit here is a true positive, exclude it
            progress("query", i, len(non_malicious), every_fp)
            continue
        tested += 1
        if bf.might_contain(url):
            false_positives += 1
        progress("query", i, len(non_malicious), every_fp)
    query_time = time.perf_counter() - t0
    q_rate = len(non_malicious) / query_time if query_time else float("inf")
    print(f"  queried {len(non_malicious):,} URLs in {query_time:.3f}s "
          f"({q_rate:,.0f} URLs/s)\n")

    measured_fp = (false_positives / tested) if tested else 0.0

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Malicious URLs inserted       : {len(malicious):,}")
    print(f"Non-malicious URLs queried    : {len(non_malicious):,}")
    print(f"Dataset overlaps (excluded)   : {len(overlap):,}")
    print(f"Clean URLs actually tested    : {tested:,}")
    print(f"False negatives               : {false_negatives:,} "
          f"({'OK - impossible by design' if false_negatives == 0 else 'BUG!'})")
    print(f"Bloom false positives         : {false_positives:,}")
    print(f"Measured FP rate              : {measured_fp:.4%}")
    print(f"Target FP rate                : {TARGET_FP_RATE:.4%}")
    print(f"Theoretical FP rate           : {bf.theoretical_fp_rate():.4%}")
    print(f"Insertion time                : {insert_time:.3f}s "
          f"({ins_rate:,.0f} URLs/s)")
    print(f"Query time                    : {query_time:.3f}s "
          f"({q_rate:,.0f} URLs/s)")
    print(f"Memory used                   : {human_bytes(bf.num_bytes)} "
          f"({bf.num_bytes * 8 / max(1, len(mal_set)):.1f} bits/URL)")
    print("=" * 60)


if __name__ == "__main__":
    main()