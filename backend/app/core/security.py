import hashlib
import os
import re
from pathlib import Path
from typing import Tuple
from backend.app.core.config import settings

SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"mark\s+this\s+case\s+as\s+conformant", re.IGNORECASE),
    re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
]


def sanitize_filename(filename: str) -> str:
    """Prevents path traversal and strips unsafe characters from uploaded filenames."""
    if not filename:
        raise ValueError("Filename cannot be empty.")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError(f"Path traversal sequence rejected in filename: {filename}")
    base = os.path.basename(filename)
    cleaned = SAFE_FILENAME_RE.sub("_", base)
    return cleaned


def validate_upload_constraints(filename: str, content: bytes) -> Tuple[str, str]:
    """Validates file extension, non-empty payload, and size limits."""
    safe_name = sanitize_filename(filename)
    ext = Path(safe_name).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise ValueError(
            f"Unsupported file extension '{ext}'. Allowed: {settings.allowed_extensions}"
        )
    if len(content) == 0:
        raise ValueError("Uploaded file is empty (0 bytes).")
    if len(content) > settings.max_upload_size_bytes:
        raise ValueError(
            f"File size {len(content)} exceeds maximum {settings.max_upload_size_bytes} bytes."
        )
    return safe_name, ext.lstrip(".")


def compute_sha256_bytes(content: bytes) -> str:
    """Computes cryptographic SHA-256 digest over raw bytes."""
    return hashlib.sha256(content).hexdigest()


def compute_sha256_file(file_path: Path) -> str:
    """Computes cryptographic SHA-256 digest over a stored file without modifying it."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_untrusted_text_for_ai(raw_text: str, record_id: str = "UNSPECIFIED") -> dict:
    """
    Implements a 4-layer defense-in-depth architecture against indirect prompt injection:
    1. Layer 1 (Pattern Detection): Heuristic & regex detection of adversarial control phrases.
    2. Layer 2 (Structural Privilege Isolation): Encapsulates untrusted telemetry inside non-executable
       XML data tags (<untrusted_evidence_record>) separated from system instructions.
    3. Layer 3 (Constrained Schema Validation): Downstream verifier requires valid database record IDs.
    4. Layer 4 (Human Verification Gate): All AI findings remain PENDING_HUMAN_REVIEW until auditor sign-off.
    Note: Regex filtering is only Layer 1 and is never treated as standalone protection.
    """
    if not raw_text:
        return {
            "sanitized_text": "",
            "isolated_envelope": f'<untrusted_evidence_record id="{record_id}"></untrusted_evidence_record>',
            "injection_detected": False,
            "matches": [],
            "defense_layers_applied": [
                "L1_known_pattern_detection",
                "L2_structural_delimiter_isolation",
                "L3_schema_grounding_constraint",
                "L4_mandatory_human_review_gate",
            ],
        }
    matches = []
    sanitized = raw_text
    for pattern in PROMPT_INJECTION_PATTERNS:
        found = pattern.findall(sanitized)
        if found:
            matches.append(pattern.pattern)
            sanitized = pattern.sub("[REDACTED_UNTRUSTED_DIRECTIVE]", sanitized)
    sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
    isolated_envelope = (
        f'<untrusted_evidence_record id="{record_id}" trust_level="untrusted_data_only">\n'
        f"  {sanitized}\n"
        f"</untrusted_evidence_record>"
    )
    return {
        "sanitized_text": sanitized,
        "isolated_envelope": isolated_envelope,
        "injection_detected": len(matches) > 0,
        "matches": matches,
        "defense_layers_applied": [
            "L1_known_pattern_detection",
            "L2_structural_delimiter_isolation",
            "L3_schema_grounding_constraint",
            "L4_mandatory_human_review_gate",
        ],
    }
