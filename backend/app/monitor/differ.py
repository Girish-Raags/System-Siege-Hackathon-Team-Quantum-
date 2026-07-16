"""
Content change detection. Produces a 0-100 "change score" describing how
different the current snapshot is from a reference snapshot, plus a short
human-readable unified diff excerpt for alerting / AI analysis.
"""
import difflib


def compute_change_score(reference_text: str, current_text: str) -> float:
    """0 = identical, 100 = completely different."""
    if not reference_text and not current_text:
        return 0.0
    matcher = difflib.SequenceMatcher(None, reference_text, current_text)
    similarity = matcher.ratio()  # 1.0 = identical
    return round((1.0 - similarity) * 100, 2)


def build_diff_excerpt(reference_text: str, current_text: str, max_lines: int = 40) -> str:
    ref_lines = reference_text.splitlines()
    cur_lines = current_text.splitlines()
    diff = list(difflib.unified_diff(ref_lines, cur_lines, lineterm="", n=1))
    if not diff:
        # Fall back to word-level diff for single-line HTML blobs.
        ref_words = reference_text.split()
        cur_words = current_text.split()
        diff = list(difflib.unified_diff(ref_words, cur_words, lineterm=" ", n=3))
    return "\n".join(diff[:max_lines])
