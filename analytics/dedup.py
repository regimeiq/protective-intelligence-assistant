"""
Content Deduplication Engine.

Two-tier approach:
1. Fast path: SHA-256 content hash — catches exact/near-exact duplicates in O(1)
2. Slow path: Fuzzy title matching via SequenceMatcher — catches rephrased duplicates

Only the slow path runs if the fast path misses. Fuzzy matching is limited to
same-day candidates (max 200) to keep it bounded.
"""

import hashlib
import re
from difflib import SequenceMatcher


def normalize_text(text):
    """
    Normalize text for hashing: strip HTML tags, lowercase, collapse whitespace.
    Returns first 200 characters of normalized text.
    """
    if not text:
        return ""
    # Strip HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text[:200]


def compute_content_hash(title, content):
    """
    SHA-256 hash of normalized (title + content).
    Used as fast-path dedup key.
    """
    normalized = normalize_text(f"{title or ''} {content or ''}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def find_content_hash_duplicate(conn, content_hash):
    """
    Fast path: look up an existing alert with the same content hash.
    Returns the alert ID if found, None otherwise.
    """
    row = conn.execute(
        """SELECT id FROM alerts
        WHERE content_hash = ? AND duplicate_of IS NULL
        LIMIT 1""",
        (content_hash,),
    ).fetchone()
    return row["id"] if row else None


def find_fuzzy_title_duplicate(conn, title, threshold=0.85, max_candidates=200):
    """
    Slow path: fuzzy title matching using SequenceMatcher.
    Limited to same-day alerts to keep search bounded.

    Args:
        conn: Database connection
        title: Title to match against
        threshold: Minimum similarity ratio (0.0-1.0, default 0.85)
        max_candidates: Maximum candidates to compare against

    Returns:
        Alert ID of the best match above threshold, or None.
    """
    if not title:
        return None

    from datetime import datetime

    today = datetime.utcnow().strftime("%Y-%m-%d")
    candidates = conn.execute(
        """SELECT id, title FROM alerts
        WHERE created_at >= ? AND duplicate_of IS NULL
        ORDER BY id DESC LIMIT ?""",
        (today, max_candidates),
    ).fetchall()

    title_lower = title.lower().strip()
    best_match = None
    best_ratio = 0.0

    for candidate in candidates:
        candidate_title = (candidate["title"] or "").lower().strip()
        ratio = SequenceMatcher(None, title_lower, candidate_title).ratio()
        if ratio >= threshold and ratio > best_ratio:
            best_ratio = ratio
            best_match = candidate["id"]

    return best_match


def check_duplicate(conn, title, content):
    """
    Combined dedup check: fast hash path, then fuzzy fallback.

    Returns:
        (content_hash, duplicate_of_id) tuple.
        duplicate_of_id is None if this is a unique alert.
    """
    content_hash = compute_content_hash(title, content)

    # Fast path: exact content hash match
    dup_id = find_content_hash_duplicate(conn, content_hash)
    if dup_id:
        return content_hash, dup_id

    # Slow path: fuzzy title match
    dup_id = find_fuzzy_title_duplicate(conn, title)
    return content_hash, dup_id
