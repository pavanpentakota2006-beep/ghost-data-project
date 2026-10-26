"""Deterministic multilingual deletion-intent classifier."""
from .config import DELETE_STEMS, NON_DELETE_PHRASES


def requests_deletion(text):
    """Determine whether request_text authorizes deletion per §6.5."""
    t = (text or "").lower()
    for nd in NON_DELETE_PHRASES:
        if nd in t:
            return False
    return any(s in t for s in DELETE_STEMS)
