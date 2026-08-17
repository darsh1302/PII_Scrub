"""Custom security recognizers for BASE_SECURITY entity types.

Guardrail G13. Addresses review finding SEC-11.

Every pattern here runs over attacker-controlled content, so each is written to
be linear-time: no nested unbounded quantifiers, bounded repetition counts, and
character classes that cannot overlap with their neighbours. A pattern like
``(\\w+\\s*)+=`` backtracks catastrophically on a crafted line and hangs the
worker; the equivalents below use explicit bounds instead.

Presidio ships recognizers for generic PII. It does not cover credentials well,
which is the gap BASE_SECURITY exists to close — a leaked API key is usually
more immediately damaging than a leaked name.
"""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer

# Bounded token character class, used everywhere a secret value is matched.
# Explicit upper bounds keep matching linear.
_TOKEN = r"[A-Za-z0-9_\-\.\+/=]"


def _kv(keys: str, value: str = f"{_TOKEN}{{8,512}}") -> str:
    """Key/value pattern with bounded separator handling.

    ``[ \\t]{0,4}`` rather than ``\\s*`` — bounded, and deliberately excludes
    newlines so a match cannot run across log lines.
    """
    return (
        rf"(?i:\b(?:{keys})\b)"
        rf"[ \t]{{0,4}}[:=][ \t]{{0,4}}"
        rf'["\']?({value})["\']?'
    )


# --------------------------------------------------------------------------
# Pattern definitions
# --------------------------------------------------------------------------
PASSWORD_PATTERNS = [
    Pattern(
        name="password_assignment",
        regex=_kv(r"password|passwd|pwd|pass", r"[^\s\"']{6,128}"),
        score=0.65,
    ),
    Pattern(
        name="password_in_url",
        regex=r"(?i://[^:/\s]{1,64}:)([^@/\s]{3,128})(?=@)",
        score=0.75,
    ),
]

PASSCODE_PATTERNS = [
    Pattern(
        name="passcode_assignment",
        regex=_kv(r"passcode|pass_code|secret_code", r"[^\s\"']{4,64}"),
        score=0.6,
    ),
]

API_KEY_PATTERNS = [
    Pattern(
        name="api_key_assignment",
        regex=_kv(r"api[_\-]?key|apikey|x[_\-]api[_\-]key|api[_\-]?secret"),
        score=0.7,
    ),
    Pattern(
        # OpenAI-style. Bounded length, single character class.
        name="openai_key",
        regex=r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,200}\b",
        score=0.85,
    ),
    Pattern(
        name="github_token",
        regex=r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        score=0.9,
    ),
    Pattern(
        name="slack_token",
        regex=r"\bxox[baprs]-[A-Za-z0-9\-]{10,250}\b",
        score=0.85,
    ),
    Pattern(
        name="stripe_key",
        regex=r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,120}\b",
        score=0.9,
    ),
    Pattern(
        name="google_api_key",
        regex=r"\bAIza[A-Za-z0-9_\-]{35}\b",
        score=0.9,
    ),
]

AWS_KEY_PATTERNS = [
    Pattern(
        name="aws_access_key_id",
        regex=r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
        score=0.85,
    ),
    Pattern(
        name="aws_secret_access_key",
        regex=_kv(
            r"aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret",
            r"[A-Za-z0-9/\+=]{40}",
        ),
        score=0.8,
    ),
]

ACCESS_TOKEN_PATTERNS = [
    Pattern(
        name="bearer_token",
        regex=rf"(?i:\bbearer)[ \t]{{1,4}}({_TOKEN}{{16,1024}})",
        score=0.75,
    ),
    Pattern(
        name="access_token_assignment",
        regex=_kv(r"access[_\-]?token|auth[_\-]?token|id[_\-]?token"),
        score=0.7,
    ),
]

REFRESH_TOKEN_PATTERNS = [
    Pattern(
        name="refresh_token_assignment",
        regex=_kv(r"refresh[_\-]?token"),
        score=0.7,
    ),
]

OAUTH_TOKEN_PATTERNS = [
    Pattern(
        name="oauth_token_assignment",
        regex=_kv(r"oauth[_\-]?token|oauth2[_\-]?token"),
        score=0.7,
    ),
]

JWT_PATTERNS = [
    Pattern(
        # Three base64url segments. Anchored on the standard header prefix so a
        # plain dotted string does not match.
        name="jwt",
        regex=(
            r"\beyJ[A-Za-z0-9_\-]{10,4000}"
            r"\.[A-Za-z0-9_\-]{10,4000}"
            r"\.[A-Za-z0-9_\-]{10,2000}\b"
        ),
        score=0.9,
    ),
]

AUTH_HEADER_PATTERNS = [
    Pattern(
        name="authorization_header",
        regex=(
            r"(?i:\bauthorization)[ \t]{0,4}:[ \t]{0,4}"
            rf"((?i:bearer|basic|token|digest)?[ \t]{{0,2}}{_TOKEN}{{8,1024}})"
        ),
        score=0.8,
    ),
    Pattern(
        name="basic_auth_value",
        regex=r"(?i:\bbasic)[ \t]{1,4}([A-Za-z0-9\+/]{16,512}={0,2})",
        score=0.75,
    ),
]

CLIENT_SECRET_PATTERNS = [
    Pattern(
        name="client_secret_assignment",
        regex=_kv(r"client[_\-]?secret|app[_\-]?secret|consumer[_\-]?secret"),
        score=0.75,
    ),
]

SESSION_COOKIE_PATTERNS = [
    Pattern(
        name="session_cookie",
        regex=_kv(
            r"session[_\-]?id|sessionid|jsessionid|phpsessid|"
            r"session[_\-]?token|csrf[_\-]?token"
        ),
        score=0.65,
    ),
    Pattern(
        name="set_cookie_header",
        regex=rf"(?i:\bset-cookie)[ \t]{{0,4}}:[ \t]{{0,4}}({_TOKEN}{{4,128}}=[^;\s]{{4,512}})",
        score=0.6,
    ),
]

PRIVATE_KEY_PATTERNS = [
    Pattern(
        # DOTALL-free: [\s\S] with a bounded count keeps this linear while still
        # crossing newlines. An RSA-4096 block is ~3.2 KB; 12000 covers it.
        name="pem_private_key",
        regex=(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]{0,12000}?"
            r"-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        score=0.95,
    ),
    Pattern(
        # Header alone still warrants flagging: a truncated log may hold only
        # the opening line, and that is enough to know a key was written.
        name="pem_private_key_header",
        regex=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
        score=0.8,
    ),
]

SSH_KEY_PATTERNS = [
    Pattern(
        name="openssh_private_key",
        regex=(
            r"-----BEGIN OPENSSH PRIVATE KEY-----"
            r"[\s\S]{0,12000}?"
            r"-----END OPENSSH PRIVATE KEY-----"
        ),
        score=0.95,
    ),
    Pattern(
        name="ssh_private_key_body",
        regex=r"\bb3BlbnNzaC1rZXktdjE[A-Za-z0-9\+/=]{20,8000}",
        score=0.85,
    ),
]

DB_CREDENTIAL_PATTERNS = [
    Pattern(
        name="db_password_assignment",
        regex=_kv(
            r"db[_\-]?password|database[_\-]?password|"
            r"mysql[_\-]?password|postgres[_\-]?password|pg[_\-]?password",
            r"[^\s\"']{4,128}",
        ),
        score=0.75,
    ),
]

CLOUD_CREDENTIAL_PATTERNS = [
    Pattern(
        name="gcp_service_account_key",
        regex=r'"private_key_id"[ \t]{0,4}:[ \t]{0,4}"[a-f0-9]{40}"',
        score=0.85,
    ),
    Pattern(
        name="azure_storage_key",
        regex=_kv(r"accountkey|account[_\-]?key", r"[A-Za-z0-9\+/]{60,120}={0,2}"),
        score=0.8,
    ),
]

CONNECTION_STRING_PATTERNS = [
    Pattern(
        # Credential-bearing URI. The (?=@) lookahead avoids consuming the host,
        # keeping the match bounded to the credential portion.
        name="uri_with_credentials",
        regex=(
            r"\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|"
            r"amqp|amqps|ftp|ftps|sftp|mssql|oracle|clickhouse)"
            r"://[^:/\s]{1,64}:[^@/\s]{1,128}@[^\s/]{1,255}"
        ),
        score=0.9,
    ),
    Pattern(
        name="odbc_connection_string",
        regex=(
            r"(?i:\b(?:Server|Data Source)\b)[ \t]{0,4}=[^;]{1,128};"
            r"[^;]{0,256}?(?i:\b(?:Password|Pwd)\b)[ \t]{0,4}=[^;\s]{1,128}"
        ),
        score=0.85,
    ),
]


_DEFINITIONS: list[tuple[str, list[Pattern], list[str]]] = [
    ("PASSWORD", PASSWORD_PATTERNS, ["password", "passwd", "pwd", "credentials"]),
    ("PASSCODE", PASSCODE_PATTERNS, ["passcode", "code"]),
    ("API_KEY", API_KEY_PATTERNS, ["api", "key", "token", "secret"]),
    ("AWS_ACCESS_KEY", AWS_KEY_PATTERNS, ["aws", "access", "key", "amazon"]),
    ("ACCESS_TOKEN", ACCESS_TOKEN_PATTERNS, ["token", "bearer", "authorization"]),
    ("REFRESH_TOKEN", REFRESH_TOKEN_PATTERNS, ["refresh", "token"]),
    ("OAUTH_TOKEN", OAUTH_TOKEN_PATTERNS, ["oauth", "token"]),
    ("JWT", JWT_PATTERNS, ["jwt", "token", "bearer"]),
    ("AUTHORIZATION_HEADER", AUTH_HEADER_PATTERNS, ["authorization", "header"]),
    ("CLIENT_SECRET", CLIENT_SECRET_PATTERNS, ["client", "secret", "oauth"]),
    ("SESSION_COOKIE", SESSION_COOKIE_PATTERNS, ["session", "cookie", "csrf"]),
    ("PRIVATE_KEY", PRIVATE_KEY_PATTERNS, ["private", "key", "pem", "begin"]),
    ("SSH_PRIVATE_KEY", SSH_KEY_PATTERNS, ["ssh", "openssh", "private", "key"]),
    ("DATABASE_CREDENTIAL", DB_CREDENTIAL_PATTERNS, ["database", "db", "password"]),
    ("CLOUD_CREDENTIAL", CLOUD_CREDENTIAL_PATTERNS, ["service", "account", "key"]),
    (
        "CONNECTION_STRING",
        CONNECTION_STRING_PATTERNS,
        ["connection", "string", "server", "datasource"],
    ),
]


def build_security_recognizers() -> list[PatternRecognizer]:
    """Construct all BASE_SECURITY recognizers."""
    recognizers: list[PatternRecognizer] = []
    for entity, patterns, context in _DEFINITIONS:
        recognizers.append(
            PatternRecognizer(
                supported_entity=entity,
                name=f"{entity}_recognizer",
                patterns=patterns,
                context=context,
            )
        )
    return recognizers


def security_entity_types() -> tuple[str, ...]:
    return tuple(entity for entity, _, _ in _DEFINITIONS)


# --------------------------------------------------------------------------
# Linearity self-check
# --------------------------------------------------------------------------
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*]\)[+*]")


def audit_pattern_linearity() -> list[str]:
    """Flag patterns whose shape suggests catastrophic backtracking.

    A structural check, not a proof. The behavioural guarantee comes from
    ``test_redos_time_bounded``, which runs adversarial input against each
    pattern under a wall-clock budget. This exists so a newly-added pattern with
    an obvious nested quantifier is caught during review.
    """
    suspicious: list[str] = []
    for entity, patterns, _ in _DEFINITIONS:
        for pattern in patterns:
            if _NESTED_QUANTIFIER.search(pattern.regex):
                suspicious.append(f"{entity}.{pattern.name}: nested quantifier")
            if ".*" in pattern.regex or ".+" in pattern.regex:
                suspicious.append(
                    f"{entity}.{pattern.name}: unbounded dot-star"
                )
    return suspicious
