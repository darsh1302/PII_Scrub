"""Component health reporting.

Requirement 36.1. Addresses the gap noted after the API-key episode: startup
validation checked the *shape* of the OpenAI key but not whether the account
could actually serve a request, so it reported healthy on an unusable
configuration.

LLM liveness is therefore checked here, on demand, rather than at startup — it
costs a token and a round trip, so it should not run on every launch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from utils.config import Settings, detect_engine_versions


class Health(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"

    @property
    def icon(self) -> str:
        return {
            "OK": "🟢",
            "DEGRADED": "🟡",
            "UNAVAILABLE": "🔴",
            "UNKNOWN": "⚪",
        }[self.value]


@dataclass
class ComponentHealth:
    name: str
    status: Health
    detail: str = ""
    blocks_scrubbing: bool = False


def check_presidio() -> ComponentHealth:
    try:
        from core.detector import get_analyzer

        get_analyzer()
    except Exception as exc:
        return ComponentHealth(
            name="Presidio engine",
            status=Health.UNAVAILABLE,
            detail=f"{exc.__class__.__name__} — pattern detection is unavailable",
            blocks_scrubbing=True,
        )
    return ComponentHealth("Presidio engine", Health.OK, "Pattern detection ready")


def check_spacy() -> ComponentHealth:
    from core.detector import DetectorUnavailable, get_spacy

    try:
        get_spacy()
    except DetectorUnavailable as exc:
        return ComponentHealth(
            name="spaCy model",
            status=Health.UNAVAILABLE,
            detail=str(exc),
            # Profiles that declare spaCy required become unavailable rather
            # than silently reduced in scope.
            blocks_scrubbing=True,
        )
    except Exception as exc:
        return ComponentHealth(
            name="spaCy model",
            status=Health.UNAVAILABLE,
            detail=f"{exc.__class__.__name__}",
            blocks_scrubbing=True,
        )
    return ComponentHealth("spaCy model", Health.OK, "Contextual detection ready")


def check_engine_versions() -> ComponentHealth:
    from utils.config import verify_engine_versions

    mismatches = verify_engine_versions()
    if mismatches:
        return ComponentHealth(
            name="Engine versions",
            status=Health.DEGRADED,
            detail=(
                "Installed versions differ from the pins recorded in audit "
                "records, so results are not reproducible: "
                + "; ".join(mismatches)
            ),
        )
    found = detect_engine_versions()
    return ComponentHealth(
        name="Engine versions",
        status=Health.OK,
        detail=f"Presidio {found.get('presidio-analyzer')}, spaCy {found.get('spacy')}",
    )


def check_profiles() -> ComponentHealth:
    from core.profile_resolver import get_resolver

    resolver = get_resolver()
    names = resolver.available_profiles()
    if not names:
        return ComponentHealth(
            name="Profiles",
            status=Health.UNAVAILABLE,
            detail="No profile files found",
            blocks_scrubbing=True,
        )

    broken: list[str] = []
    for name in names:
        try:
            resolver.resolve(name)
        except Exception as exc:
            broken.append(f"{name} ({exc.__class__.__name__})")

    if broken:
        return ComponentHealth(
            name="Profiles",
            status=Health.DEGRADED,
            detail="Failed validation: " + ", ".join(broken),
        )
    return ComponentHealth(
        name="Profiles", status=Health.OK, detail=f"{len(names)} loaded"
    )


def check_audit_sink(settings: Settings) -> ComponentHealth:
    try:
        settings.audit_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.audit_dir / ".health_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return ComponentHealth(
            name="Audit trail",
            status=Health.UNAVAILABLE,
            detail=f"Not writable ({exc.__class__.__name__})",
            blocks_scrubbing=True,
        )
    return ComponentHealth("Audit trail", Health.OK, str(settings.audit_dir))


def check_scan_roots(settings: Settings) -> ComponentHealth:
    if not settings.scan_roots:
        return ComponentHealth(
            name="Scan roots",
            status=Health.DEGRADED,
            detail="None configured — only uploaded files can be scanned",
        )
    missing = [str(r) for r in settings.scan_roots if not r.is_dir()]
    if missing:
        return ComponentHealth(
            name="Scan roots",
            status=Health.DEGRADED,
            detail="Missing: " + ", ".join(missing),
        )
    return ComponentHealth(
        name="Scan roots",
        status=Health.OK,
        detail=f"{len(settings.scan_roots)} configured",
    )


def check_llm(settings: Settings, *, probe: bool = False) -> ComponentHealth:
    """Check the LLM. Shape only unless ``probe`` is set.

    A live probe costs a token, so it is opt-in. Without it we can only report
    that a key is present — which is what previously reported healthy on an
    account with no credit.
    """
    if not settings.has_openai_key:
        return ComponentHealth(
            name="LLM (gpt-4o)",
            status=Health.UNAVAILABLE,
            detail="OPENAI_API_KEY is not set — conversation is unavailable. "
            "Scanning and scrubbing still work.",
        )

    if settings.openai_key_is_placeholder:
        return ComponentHealth(
            name="LLM (gpt-4o)",
            status=Health.UNAVAILABLE,
            detail="OPENAI_API_KEY is still a template placeholder",
        )

    if not probe:
        return ComponentHealth(
            name="LLM (gpt-4o)",
            status=Health.UNKNOWN,
            detail="Key present. Run a live check to confirm the account can "
            "serve requests.",
        )

    try:
        from langchain_openai import ChatOpenAI

        reply = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=5).invoke(
            "Reply with: ok"
        )
        _ = reply
    except Exception as exc:
        name = exc.__class__.__name__
        if "RateLimit" in name or "quota" in str(exc).lower():
            detail = (
                "The key is valid but the account has no available quota. Add "
                "credit at platform.openai.com — API billing is separate from "
                "a ChatGPT subscription."
            )
        elif "Authentication" in name:
            detail = "The key was rejected. Check it has not been revoked."
        else:
            from utils.content_gate import sanitize_error

            detail = sanitize_error(exc)
        return ComponentHealth("LLM (gpt-4o)", Health.UNAVAILABLE, detail)

    return ComponentHealth("LLM (gpt-4o)", Health.OK, "Reachable")


def collect_health(
    settings: Settings, *, probe_llm: bool = False
) -> list[ComponentHealth]:
    return [
        check_presidio(),
        check_spacy(),
        check_profiles(),
        check_engine_versions(),
        check_audit_sink(settings),
        check_scan_roots(settings),
        check_llm(settings, probe=probe_llm),
    ]


def overall_status(components: list[ComponentHealth]) -> Health:
    if any(c.status is Health.UNAVAILABLE for c in components):
        return Health.UNAVAILABLE
    if any(c.status is Health.DEGRADED for c in components):
        return Health.DEGRADED
    if any(c.status is Health.UNKNOWN for c in components):
        return Health.UNKNOWN
    return Health.OK


def scrubbing_blockers(components: list[ComponentHealth]) -> list[ComponentHealth]:
    """Components whose failure prevents producing a cleaned artifact.

    Distinct from overall status: a missing LLM stops conversation but not
    scrubbing, whereas a missing spaCy model stops scrubbing for any profile
    that requires it.
    """
    return [c for c in components if c.blocks_scrubbing and c.status is not Health.OK]
