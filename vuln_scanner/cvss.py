"""CVSS score -> qualitative severity mapping helpers."""

from .config import CVSS_V3_BANDS


def severity_from_cvss(score):
    """Map a numeric CVSS (v2 or v3) base score to Critical/High/Medium/Low/Info."""
    if score is None:
        return "Info"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Info"
    if score <= 0:
        return "Info"
    for low, high, label in CVSS_V3_BANDS:
        if low <= score <= high:
            return label
    return "Info"


def best_cvss_from_metrics(metrics):
    """
    Given an NVD `metrics` dict (as returned by the CVE 2.0 API), pick the
    best available CVSS score/vector, preferring v3.1 > v3.0 > v2.

    Returns (score: float|None, version: str|None, vector: str|None).
    """
    if not metrics:
        return None, None, None
    for key, version_label in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            return score, version_label, vector
    return None, None, None
