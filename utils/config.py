"""Configuration and environment loading.

Secrets are loaded from .env via python-dotenv and are never echoed. The
``Settings`` dataclass deliberately omits secret values from ``repr`` so that a
stray log line or exception cannot leak them (Requirement 17.4).

Engine versions are pinned and verified at startup because they are recorded in
every ProcessingResult and AuditRecord — a silent engine upgrade would change
detection output and invalidate historical compliance claims (Requirement 46.7,
guardrail G21).
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


# --------------------------------------------------------------------------
# LLM
# --------------------------------------------------------------------------
LLM_MODEL = "gpt-4o"
LLM_TEMPERATURE = 0
LLM_MAX_TOKENS = 4096

# --------------------------------------------------------------------------
# Agent budgets (guardrails G22, G23)
# --------------------------------------------------------------------------
MAX_REASONING_ITERATIONS = 10
MAX_CONTENT_TO_LLM_CHARS = 4000
MAX_LLM_TOKENS_PER_SESSION = 50_000
# Measured throughput is roughly 2.5 KB/s end to end, dominated by Presidio's
# lemma context enhancer and the phonenumbers matcher, and doubled by the
# verification re-scan. A 30-second tool budget therefore capped useful input at
# about 70 KB and turned ordinary log files into TIMEOUT refusals. Raised so a
# few hundred KB completes; the turn budget stays above it so a single scan can
# use the whole tool allowance.
PER_TOOL_TIMEOUT_SECONDS = 180
PER_TURN_TIMEOUT_SECONDS = 300

# Per-chunk detection budget. Scales with chunk size because Presidio runs ~40
# recognizers plus spaCy NER over every byte: a flat budget that suits a 1 KB
# chunk falsely marks detectors failed on a 40 KB one, and a failed detector
# blocks artifact production. Base covers fixed overhead; the per-KB allowance
# covers the linear work.
CHUNK_TIMEOUT_BASE_SECONDS = 5.0
CHUNK_TIMEOUT_PER_KB_SECONDS = 0.5


def chunk_timeout_for(char_count: int) -> float:
    """Detection budget for a chunk of ``char_count`` characters."""
    return CHUNK_TIMEOUT_BASE_SECONDS + (
        (char_count / 1024) * CHUNK_TIMEOUT_PER_KB_SECONDS
    )

# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
DEFAULT_CONFIDENCE_THRESHOLD = 0.4

# --------------------------------------------------------------------------
# File processing
# --------------------------------------------------------------------------
MAX_FILE_SIZE_MB = 50
MAX_TEXT_LENGTH_CHARS = 100_000
FILE_CHUNK_SIZE_BYTES = 8192
# Floor for chunk overlap. The effective value is derived per-profile from
# max_pattern_span (guardrail G17) — a PEM private key runs 1700+ chars and an
# RSA-4096 block far more, so a small constant would split it undetected.
MIN_CHUNK_OVERLAP_CHARS = 4096
SUPPORTED_FILE_EXTENSIONS = frozenset(
    {".txt", ".log", ".json", ".jsonl", ".csv", ".xml"}
)

# Structured-parsing limits (guardrail G12)
MAX_JSON_DEPTH = 100
MAX_JSON_NODES = 500_000
MAX_CSV_FIELDS = 1000
MAX_CSV_ROW_CHARS = 100_000

# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------
MAX_EVENTS_PER_RETRIEVAL = 1000

# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------
TEMP_DIR_PREFIX = "pii_agent_"
ORPHAN_TEMP_DIR_MAX_AGE_HOURS = 24
CONTENT_HANDLE_ENTROPY_BYTES = 16  # 128-bit (guardrail G16)
TOKEN_SURROGATE_ENTROPY_BYTES = 16
HASH_KDF_ITERATIONS = 200_000  # PBKDF2 rounds; HASH is pseudonymisation only

# Sensitive paths refused regardless of configured scan root (guardrail G8).
SENSITIVE_PATH_PATTERNS = (
    ".env",
    ".env.*",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*.pem",
    "*.pfx",
    "*.p12",
    "*.key",
    "credentials",
    "credentials.*",
    ".htpasswd",
    "*.kdbx",
)
SENSITIVE_PATH_DIRS = (
    ".aws",
    ".ssh",
    ".kube",
    ".gnupg",
    ".docker",
    ".azure",
    ".config/gcloud",
)

# --------------------------------------------------------------------------
# Action priority — single authoritative ordering.
# Higher value == more restrictive. Policy resolution is max() over this map,
# which is what makes the ratchet in PolicyEngine monotonic (guardrail G4).
# --------------------------------------------------------------------------
ACTION_PRIORITY = {
    "ALLOW": 1,
    "REPLACE": 2,
    "MASK": 3,
    "HASH": 4,
    "TOKENIZE": 5,
    "REDACT": 6,
    "BLOCK": 7,
}

# --------------------------------------------------------------------------
# Pinned engine versions — must match requirements.txt exactly.
# --------------------------------------------------------------------------
PINNED_VERSIONS = {
    "presidio-analyzer": "2.2.364",
    "presidio-anonymizer": "2.2.364",
    "spacy": "3.8.15",
    "en-core-web-lg": "3.8.0",
}

# The NER model is env-overridable so a memory-constrained deployment can trade
# recall for footprint. `en_core_web_lg` is ~600 MB resident and is the default;
# `en_core_web_sm` is ~12 MB and detects noticeably fewer names.
#
# This is a real accuracy tradeoff, not a tuning knob, so the model actually used
# is recorded in every ProcessingResult and audit record. A result produced with
# the small model must not be mistaken later for one produced with the large one.
DEFAULT_SPACY_MODEL = "en_core_web_lg"
SPACY_MODEL_NAME = os.getenv("PII_AGENT_SPACY_MODEL", DEFAULT_SPACY_MODEL).strip()

# Reduced-capability public demo. Uploads only, no filesystem reach, smaller
# inputs, and a visible banner. Never a substitute for authentication — it limits
# what an anonymous visitor can reach, it does not establish who they are.
DEMO_MODE = os.getenv("PII_AGENT_DEMO_MODE", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Demo caps. The public runner throttles above ~690 MB with 2 CPU cores, and
# throughput is ~2.4 KB/s, so a large upload would be killed mid-scan and look
# like a crash rather than a limit.
DEMO_MAX_UPLOAD_BYTES = 65_536
DEMO_MAX_TEXT_CHARS = 20_000


class ConfigError(RuntimeError):
    """Raised when configuration is missing or unsafe. Never contains secrets."""


# Substrings that indicate an unreplaced template value rather than a real
# secret. Matched case-insensitively against the whole value.
_PLACEHOLDER_MARKERS = (
    "your-api-key",
    "your_api_key",
    "yourapikey",
    "changeme",
    "change-me",
    "change_me",
    "replace-me",
    "replace_me",
    "placeholder",
    "todo",
    "xxxxx",
    "<your",
    "example",
    "dummy",
    "sk-...",
    "sk-xxx",
)


def is_placeholder_secret(value: str) -> bool:
    """Detect an unreplaced template value.

    Deliberately conservative: it only flags values containing an obvious
    marker, so a real high-entropy secret is never rejected. Note the check is
    on the value's *shape*, and the value itself is never logged.
    """
    if not value:
        return False
    lowered = value.strip().lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


@dataclass
class Settings:
    """Resolved runtime configuration.

    Secret values are stored but excluded from ``repr`` so that logging a
    Settings instance cannot disclose them.
    """

    openai_api_key: str = field(repr=False, default="")
    token_vault_salt: bytes = field(repr=False, default=b"")
    scan_roots: tuple[Path, ...] = ()
    bind_address: str = "127.0.0.1"
    allow_remote: bool = False
    audit_dir: Path = Path("audit")
    aws_region: str = "us-east-1"

    @property
    def has_openai_key(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def openai_key_is_placeholder(self) -> bool:
        """True when the key is an unreplaced template value.

        A non-empty placeholder passes a naive truthiness check and then fails
        later as an opaque 401 from the API. Catching it at startup turns a
        confusing runtime error into an actionable configuration message.
        """
        return is_placeholder_secret(self.openai_api_key)

    @property
    def salt_is_placeholder(self) -> bool:
        return bool(self.token_vault_salt) and is_placeholder_secret(
            self.token_vault_salt.decode("utf-8", errors="replace")
        )

    @property
    def is_loopback_bind(self) -> bool:
        try:
            return ipaddress.ip_address(self.bind_address).is_loopback
        except ValueError:
            # Hostnames: only literal localhost is treated as loopback.
            return self.bind_address.lower() in {"localhost", ""}


def _parse_bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_scan_roots(raw: str | None) -> tuple[Path, ...]:
    """Parse and canonicalise the scan-root allowlist.

    An empty allowlist is intentionally permitted here and means "uploads only".
    It does NOT mean "whole filesystem" — the path resolver refuses any path
    that is not inside a configured root.
    """
    if not raw or not raw.strip():
        return ()
    roots: list[Path] = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        roots.append(Path(part).expanduser().resolve())
    return tuple(roots)


def load_settings() -> Settings:
    """Load settings from the environment. Does not validate — see startup.py."""
    salt_raw = os.getenv("PII_AGENT_TOKEN_VAULT_SALT", "")

    # Demo mode removes filesystem reach entirely rather than relying on the
    # operator having configured narrow roots. An anonymous visitor on a shared
    # host should not be able to name a path at all: with no roots, every path is
    # refused by containment and only uploads work.
    roots = () if DEMO_MODE else _parse_scan_roots(os.getenv("PII_AGENT_SCAN_ROOTS"))

    return Settings(
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        token_vault_salt=salt_raw.encode("utf-8"),
        scan_roots=roots,
        bind_address=os.getenv("PII_AGENT_BIND_ADDRESS", "127.0.0.1").strip(),
        allow_remote=_parse_bool(os.getenv("PII_AGENT_ALLOW_REMOTE"), False),
        audit_dir=Path(os.getenv("PII_AGENT_AUDIT_DIR", "audit")).expanduser(),
        aws_region=os.getenv("AWS_DEFAULT_REGION", "us-east-1").strip(),
    )


# --------------------------------------------------------------------------
# Engine version detection
# --------------------------------------------------------------------------
def detect_engine_versions() -> dict[str, str]:
    """Return installed versions of the pinned detection engines."""
    import importlib.metadata as md

    found: dict[str, str] = {}
    for package in PINNED_VERSIONS:
        try:
            found[package] = md.version(package)
        except md.PackageNotFoundError:
            found[package] = "MISSING"
    return found


def verify_engine_versions() -> list[str]:
    """Compare installed against pinned versions.

    Returns a list of human-readable mismatch descriptions. Empty means the
    installed environment matches the pins recorded in audit records.
    """
    installed = detect_engine_versions()
    mismatches: list[str] = []

    # An intentionally substituted NER model is not a version mismatch. It is
    # reported separately by engine_substitutions() and must not appear here:
    # startup treats anything this function returns as a hard block, so folding a
    # deliberate choice in would refuse to start over a configuration the
    # operator made on purpose.
    skip = DEFAULT_SPACY_MODEL.replace("_", "-") if _model_substituted() else None

    for package, expected in PINNED_VERSIONS.items():
        if package == skip:
            continue
        actual = installed.get(package, "MISSING")
        if actual != expected:
            mismatches.append(
                f"{package}: pinned {expected}, installed {actual}"
            )
    return mismatches


def _model_substituted() -> bool:
    return SPACY_MODEL_NAME != DEFAULT_SPACY_MODEL


def engine_substitutions() -> list[str]:
    """Deliberate, disclosed capability reductions.

    Separate from version mismatches because the severity differs. A mismatch
    means results would not be reproducible and processing must not proceed. A
    substitution means the operator chose lower recall, which is a warning the
    user should see but not a reason to refuse to start.
    """
    if not _model_substituted():
        return []

    installed = detect_engine_versions()
    version = installed.get(SPACY_MODEL_NAME.replace("_", "-"), "unknown")
    if version == "MISSING":
        return [
            f"NER model {SPACY_MODEL_NAME} is configured but not installed. "
            f"Run: pip install -r requirements.txt"
        ]

    return [
        f"NER model {SPACY_MODEL_NAME} in use instead of the default "
        f"{DEFAULT_SPACY_MODEL} — fewer personal names will be detected. "
        f"Recorded in every result and audit record."
    ]
