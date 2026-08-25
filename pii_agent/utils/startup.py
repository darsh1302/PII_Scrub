"""Startup validation and environment hygiene.

Guardrails G10, G21, G24. Requirement 44.

The binding check exists because this service reads the local filesystem and
pulls CloudWatch logs using the host's credentials, with no authentication of
its own. Bound to 0.0.0.0 — the default in many container images — any network
peer gets file read and cloud log read as the service account. RBAC is Phase 2,
but refusing to start in that configuration is MVP.

DEPLOYMENT NOTE
---------------
Non-loopback deployment requires an authenticating reverse proxy in front of
this app. Setting PII_AGENT_ALLOW_REMOTE=true without one exposes filesystem and
cloud-log read access to anyone who can reach the port.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pii_agent.session.context import sweep_orphan_temp_dirs
from pii_agent.utils.config import (
    ConfigError,
    Settings,
    engine_substitutions,
    load_settings,
    verify_engine_versions,
)


@dataclass
class StartupReport:
    """Outcome of validation. ``ok`` false means do not serve traffic."""

    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    orphans_removed: int = 0

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.ok = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def summary(self) -> str:
        lines: list[str] = []
        if self.errors:
            lines.append("Startup blocked:")
            lines.extend(f"  ERROR  {e}" for e in self.errors)
        if self.warnings:
            lines.append("Warnings:")
            lines.extend(f"  WARN   {w}" for w in self.warnings)
        if self.ok and not self.warnings:
            lines.append("Startup validation passed.")
        return "\n".join(lines)


def validate_startup(
    settings: Settings | None = None, *, sweep: bool = True
) -> StartupReport:
    """Validate configuration before serving. Never raises on policy failure."""
    settings = settings or load_settings()
    report = StartupReport()

    # --- Secrets (Requirement 17.2, 44.5) -----------------------------------
    if not settings.has_openai_key:
        report.add_error(
            "OPENAI_API_KEY is not set. Add it to .env — the agent cannot "
            "reason without it. Note the deterministic scrub core does not "
            "need it; only conversational orchestration does."
        )
    elif settings.openai_key_is_placeholder:
        report.add_error(
            "OPENAI_API_KEY still contains a template placeholder rather than "
            "a real key. Replace it in .env.\n"
            "         Left unset, this surfaces later as an opaque 401 from "
            "the API rather than a configuration error."
        )

    if not settings.token_vault_salt:
        report.add_warning(
            "PII_AGENT_TOKEN_VAULT_SALT is not set. A random per-process salt "
            "will be used, so HASH output will not be stable across restarts.\n"
            "         Generate one with: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )
    elif settings.salt_is_placeholder:
        report.add_error(
            "PII_AGENT_TOKEN_VAULT_SALT contains a template placeholder. A "
            "predictable salt defeats the purpose of salting — hashed values "
            "become trivially reversible via precomputed tables."
        )
    elif len(settings.token_vault_salt) < 16:
        report.add_warning(
            f"PII_AGENT_TOKEN_VAULT_SALT is short "
            f"({len(settings.token_vault_salt)} bytes). Use at least 16 bytes "
            "of random data."
        )

    # --- Network exposure (Requirement 44.1-44.3, guardrail G10) ------------
    if not settings.is_loopback_bind and not settings.allow_remote:
        report.add_error(
            f"Refusing to start: bind address {settings.bind_address!r} is not "
            "loopback and PII_AGENT_ALLOW_REMOTE is not enabled.\n"
            "         This service reads the local filesystem and CloudWatch "
            "logs using the host's credentials and has no authentication of "
            "its own. On a non-loopback address, any network peer would gain "
            "that access.\n"
            "         Either bind 127.0.0.1, or put an authenticating reverse "
            "proxy in front and set PII_AGENT_ALLOW_REMOTE=true."
        )
    elif not settings.is_loopback_bind and settings.allow_remote:
        report.add_warning(
            f"Bound to {settings.bind_address!r} with remote access enabled. "
            "Verify an authenticating reverse proxy is in front of this app — "
            "it has filesystem and cloud-log read access."
        )

    # --- Scan roots (guardrail G8) -----------------------------------------
    if not settings.scan_roots:
        report.add_warning(
            "PII_AGENT_SCAN_ROOTS is empty. Only uploaded files can be "
            "scanned; local file paths will be refused."
        )
    else:
        for root in settings.scan_roots:
            if not root.exists():
                report.add_warning(f"Configured scan root does not exist: {root}")
            elif not root.is_dir():
                report.add_error(f"Configured scan root is not a directory: {root}")

    # --- Engine version pins (Requirement 44.5, guardrail G21) -------------
    mismatches = verify_engine_versions()
    if mismatches:
        report.add_error(
            "Installed detection engine versions do not match the pins "
            "recorded in audit records. Detection output would not be "
            "reproducible.\n         "
            + "\n         ".join(mismatches)
            + "\n         Run: pip install -r requirements.txt"
        )

    # A deliberately reduced NER model is a warning, not a block. The operator
    # chose it; refusing to start would make a supported configuration unusable.
    for substitution in engine_substitutions():
        report.add_warning(substitution)

    # --- Audit sink writability (Requirement 41.3) -------------------------
    try:
        settings.audit_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.audit_dir / ".write_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        report.add_error(
            f"Audit directory {settings.audit_dir} is not writable "
            f"({exc.__class__.__name__}). Processing must not proceed without "
            "a durable audit trail."
        )

    # --- Orphan temp sweep (Requirement 44.6, guardrail G24) ---------------
    if sweep:
        try:
            report.orphans_removed = sweep_orphan_temp_dirs()
        except OSError:  # pragma: no cover - filesystem edge
            report.add_warning("Could not sweep orphaned temp directories.")

    return report


def require_valid_startup(settings: Settings | None = None) -> StartupReport:
    """Validate and raise ConfigError if unsafe. For non-UI entry points."""
    report = validate_startup(settings)
    if not report.ok:
        raise ConfigError(report.summary())
    return report
