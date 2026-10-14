"""Bounded offline UCSC chain reader for the reviewed SCI02 source contract.

Only unique intervals wholly contained in one ungapped alignment block map.
Distinct chains are ambiguous even when their target coordinates coincide.
This module neither fetches references nor validates biological effect alleles.
"""
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import gzip
import hashlib
import io
import os
from pathlib import Path
import stat
import zlib

MAX_COMPRESSED_BYTES = 8 << 20
MAX_EXPANDED_BYTES = 64 << 20
MAX_CHAINS = 100000
MAX_BLOCKS = 1000000
MAX_LINE_BYTES = 8192


class ChainError(ValueError):
    """Stable code without private paths or source content."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _limit(value):
    if not _integer(value) or value <= 0:
        raise ChainError("limit_invalid")
    return value


def _number(token):
    # Reject signs, floats and Unicode numeric spellings.
    if not token or any(c not in "0123456789" for c in token):
        raise ChainError("integer_invalid")
    try:
        return int(token)
    except ValueError as exc:
        raise ChainError("integer_invalid") from exc


@dataclass(frozen=True)
class _Chain:
    chain_id: int
    source_chrom: str
    source_size: int
    source_start: int
    source_end: int
    target_chrom: str
    target_size: int
    strand: str
    target_start: int  # Chain query-strand coordinates, not forward coordinates.
    target_end: int


@dataclass(frozen=True)
class _Block:
    chain: _Chain
    start: int
    end: int
    query_start: int


class _Intervals:
    def __init__(self, entries):
        self.entries = sorted(entries, key=lambda entry: (entry[0], entry[1]))
        self.starts = [entry[0] for entry in self.entries]
        self.prefix_ends = []
        largest = -1
        for unused_start, end, unused_item in self.entries:
            largest = max(largest, end)
            self.prefix_ends.append(largest)

    def overlapping(self, start, end):
        left = bisect_right(self.prefix_ends, start)
        right = bisect_left(self.starts, end)
        return [item for block_start, block_end, item in self.entries[left:right]
                if block_start < end and start < block_end]


class ChainIndex:
    """Source-build interval index. Toy parse sources have source_sha256=None."""

    def __init__(self, chains, blocks, source_sha256=None):
        self.source_sha256 = source_sha256
        self.chain_count = len(chains)
        self.block_count = len(blocks)
        grouped_blocks, grouped_chains = {}, {}
        for block in blocks:
            grouped_blocks.setdefault(block.chain.source_chrom, []).append(
                (block.start, block.end, block))
        for chain in chains:
            grouped_chains.setdefault(chain.source_chrom, []).append(
                (chain.source_start, chain.source_end, chain))
        self._blocks = {chrom: _Intervals(items) for chrom, items in grouped_blocks.items()}
        self._chains = {chrom: _Intervals(items) for chrom, items in grouped_chains.items()}

    def map_interval(self, chrom, start, end, *, allowed_chromosomes=None,
                     require_same_chromosome=True):
        """Map a zero-based half-open interval or raise a stable ChainError.

        Partial overlap with another chain is also ambiguous: each queried base
        must have a unique block context. Spanning multiple blocks is rejected,
        including adjacent blocks; endpoints alone never establish coverage.
        """
        if (not isinstance(chrom, str) or not chrom or any(c.isspace() for c in chrom)
                or not _integer(start) or not _integer(end) or start < 0 or end <= start):
            raise ChainError("interval_invalid")
        if not isinstance(require_same_chromosome, bool):
            raise ChainError("option_invalid")
        if allowed_chromosomes is not None:
            if (not isinstance(allowed_chromosomes, (tuple, list, set, frozenset))
                    or not allowed_chromosomes
                    or any(not isinstance(c, str) or not c or any(x.isspace() for x in c)
                           for c in allowed_chromosomes)):
                raise ChainError("option_invalid")
            if chrom not in allowed_chromosomes:
                raise ChainError("contig_not_allowed")
        index = self._blocks.get(chrom)
        if index is None:
            raise ChainError("no_mapping")
        candidates = index.overlapping(start, end)
        if not candidates:
            if self._chains[chrom].overlapping(start, end):
                raise ChainError("gapped_interval")
            raise ChainError("no_mapping")
        if len({block.chain.chain_id for block in candidates}) != 1:
            raise ChainError("ambiguous_mapping")
        containing = [block for block in candidates if block.start <= start and end <= block.end]
        if len(containing) != 1:
            raise ChainError("gapped_interval")
        block = containing[0]
        chain = block.chain
        if require_same_chromosome and chain.target_chrom != chrom:
            raise ChainError("interchromosomal_mapping")
        if allowed_chromosomes is not None and chain.target_chrom not in allowed_chromosomes:
            raise ChainError("contig_not_allowed")
        query_start = block.query_start + start - block.start
        query_end = block.query_start + end - block.start
        if chain.strand == "+":
            target_start, target_end = query_start, query_end
        else:
            target_start = chain.target_size - query_end
            target_end = chain.target_size - query_start
        return {"chain_id": chain.chain_id, "strand": chain.strand,
                "source_chrom": chrom, "source_start": start, "source_end": end,
                "source_size": chain.source_size, "target_chrom": chain.target_chrom,
                "target_start": target_start, "target_end": target_end,
                "target_size": chain.target_size}

    def map_variant_peak(self, chrom, position_1based, peak_start, peak_end, *,
                         allowed_chromosomes=("chr8", "chr9")):
        """Map a VCF-position SNP and its BED focal peak with one chain context."""
        if (not _integer(position_1based) or position_1based <= 0
                or not _integer(peak_start) or not _integer(peak_end)
                or peak_start < 0 or peak_end <= peak_start):
            raise ChainError("interval_invalid")
        q = position_1based - 1
        if not peak_start <= q < peak_end:
            raise ChainError("snp_outside_peak")
        snp = self.map_interval(chrom, q, q + 1, allowed_chromosomes=allowed_chromosomes)
        peak = self.map_interval(chrom, peak_start, peak_end,
                                 allowed_chromosomes=allowed_chromosomes)
        if any(snp[key] != peak[key] for key in ("chain_id", "strand", "target_chrom")):
            raise ChainError("variant_peak_mapping_mismatch")
        if not peak["target_start"] <= snp["target_start"] < snp["target_end"] <= peak["target_end"]:
            raise ChainError("snp_outside_target_peak")
        return {"snp": snp, "peak": peak}


def _parse_lines(lines, *, max_expanded_bytes, max_chains, max_blocks):
    chains, blocks, ids = [], [], set()
    source_sizes, target_sizes = {}, {}
    current = None
    tpos = qpos = consumed = 0
    need_separator = False
    for raw in lines:
        consumed += len(raw)
        if consumed > max_expanded_bytes:
            raise ChainError("expanded_size_exceeded")
        if len(raw) > MAX_LINE_BYTES:
            raise ChainError("line_size_exceeded")
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ChainError("encoding_invalid") from exc
        elif not raw.isascii():
            raise ChainError("encoding_invalid")
        if any(ord(c) < 32 and c not in "\t\r\n" for c in raw):
            raise ChainError("encoding_invalid")
        fields = raw.split()
        if not fields:
            if current is not None:
                raise ChainError("chain_unterminated")
            need_separator = False
            continue
        if current is None:
            if need_separator:
                raise ChainError("chain_separator_missing")
            if len(fields) != 13 or fields[0] != "chain":
                raise ChainError("header_invalid")
            score, source_size, source_start, source_end, target_size, target_start, target_end, chain_id = (
                _number(fields[i]) for i in (1, 3, 5, 6, 8, 10, 11, 12))
            if (fields[4] != "+" or fields[9] not in ("+", "-")
                    or source_size <= 0 or target_size <= 0
                    or not 0 <= source_start < source_end <= source_size
                    or not 0 <= target_start < target_end <= target_size):
                raise ChainError("header_invalid")
            if chain_id in ids:
                raise ChainError("duplicate_chain_id")
            if len(chains) >= max_chains:
                raise ChainError("chain_count_exceeded")
            for sizes, chrom, size in ((source_sizes, fields[2], source_size),
                                      (target_sizes, fields[7], target_size)):
                if chrom in sizes and sizes[chrom] != size:
                    raise ChainError("chromosome_size_conflict")
                sizes[chrom] = size
            ids.add(chain_id)
            current = _Chain(chain_id, fields[2], source_size, source_start, source_end,
                             fields[7], target_size, fields[9], target_start, target_end)
            chains.append(current)
            tpos, qpos = source_start, target_start
            continue
        if len(fields) not in (1, 3):
            raise ChainError("block_invalid")
        size = _number(fields[0])
        if size <= 0:
            raise ChainError("block_invalid")
        if tpos + size > current.source_end or qpos + size > current.target_end:
            raise ChainError("block_exceeds_header")
        if len(blocks) >= max_blocks:
            raise ChainError("block_count_exceeded")
        blocks.append(_Block(current, tpos, tpos + size, qpos))
        tpos += size
        qpos += size
        if len(fields) == 3:
            dt, dq = _number(fields[1]), _number(fields[2])
            tpos += dt
            qpos += dq
            if tpos >= current.source_end or qpos >= current.target_end:
                raise ChainError("block_exceeds_header")
        else:
            if tpos != current.source_end or qpos != current.target_end:
                raise ChainError("chain_end_mismatch")
            current = None
            need_separator = True
    if current is not None:
        raise ChainError("chain_unterminated")
    if not chains:
        raise ChainError("chain_empty")
    return ChainIndex(chains, blocks)


def _lines(handle, maximum=None):
    consumed = 0
    while True:
        amount = MAX_LINE_BYTES + 1
        if maximum is not None:
            amount = min(amount, maximum - consumed + 1)
        line = handle.readline(amount)
        if not line:
            break
        consumed += len(line)
        yield line


class _BoundedCompressed:
    """Limit the second compressed pass even if a same-UID writer changes it."""

    def __init__(self, handle, maximum):
        self.handle, self.maximum, self.consumed = handle, maximum, 0
        self.sha256 = hashlib.sha256()

    def read(self, size=-1):
        remaining = self.maximum - self.consumed + 1
        block = self.handle.read(remaining if size < 0 else min(size, remaining))
        self.consumed += len(block)
        self.sha256.update(block)
        if self.consumed > self.maximum:
            raise ChainError("compressed_size_exceeded")
        return block

    def tell(self):
        return self.handle.tell()

    def fileno(self):
        return self.handle.fileno()


def parse_chain(text, *, max_chains=MAX_CHAINS, max_blocks=MAX_BLOCKS,
                max_expanded_bytes=MAX_EXPANDED_BYTES):
    """Strict parser for small ASCII toy fixtures; no file acquisition/provenance."""
    for value in (max_chains, max_blocks, max_expanded_bytes):
        _limit(value)
    if not isinstance(text, str):
        raise ChainError("text_invalid")
    if len(text) > max_expanded_bytes:
        raise ChainError("expanded_size_exceeded")
    return _parse_lines(_lines(io.StringIO(text)), max_expanded_bytes=max_expanded_bytes,
                        max_chains=max_chains, max_blocks=max_blocks)


def load_chain(path, *, expected_sha256=None, max_compressed_bytes=MAX_COMPRESSED_BYTES,
               max_expanded_bytes=MAX_EXPANDED_BYTES, max_chains=MAX_CHAINS,
               max_blocks=MAX_BLOCKS):
    """Hash a private regular gzip, seek the same descriptor, then read full CRC.

    The production caller must pass the pinned compressed digest. Filename and
    filesystem errors never enter ChainError messages. No symlink final component,
    special file, non-owner file or mode other than 0600 is admitted.
    """
    for value in (max_compressed_bytes, max_expanded_bytes, max_chains, max_blocks):
        _limit(value)
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise ChainError("sha256_invalid")
    if not isinstance(path, (str, Path)):
        raise ChainError("path_invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError) as exc:
        raise ChainError("file_open_failed") from exc
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ChainError("file_not_regular")
        if stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid():
            raise ChainError("file_not_private_owned")
        if before.st_size > max_compressed_bytes:
            raise ChainError("compressed_size_exceeded")
        sha, consumed = hashlib.sha256(), 0
        while True:
            block = handle.read(min(1 << 20, max_compressed_bytes - consumed + 1))
            if not block:
                break
            consumed += len(block)
            if consumed > max_compressed_bytes:
                raise ChainError("compressed_size_exceeded")
            sha.update(block)
        actual = sha.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise ChainError("sha256_mismatch")
        handle.seek(0)
        try:
            bounded = _BoundedCompressed(handle, max_compressed_bytes)
            with gzip.GzipFile(fileobj=bounded, mode="rb") as expanded:
                index = _parse_lines(_lines(expanded, max_expanded_bytes), max_expanded_bytes=max_expanded_bytes,
                                     max_chains=max_chains, max_blocks=max_blocks)
        except ChainError:
            raise
        except (OSError, EOFError, ValueError, zlib.error) as exc:
            raise ChainError("gzip_invalid") from exc
        after = os.fstat(handle.fileno())
        if (bounded.sha256.hexdigest() != actual or consumed != bounded.consumed
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ChainError("source_changed_during_read")
    index.source_sha256 = actual
    return index
