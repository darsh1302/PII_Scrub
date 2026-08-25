"""The six agent-visible tools.

Requirement 46.1-46.2. Guardrails G1, G4, G22.

Every tool here is handle-based. None accepts text, entity positions, or a scrub
action that could weaken policy. The agent chooses *what* to scan and *which
profile*; the deterministic core decides everything else.

``requested_action`` is accepted but documented as a request only: the Policy
Enforcement Point can ratchet it up and will discard it if weaker. Accepting it
lets a user ask for stricter handling, which is useful; the ratchet makes the
weaker direction structurally impossible.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from pii_agent.core.file_source import load_file, load_text
from pii_agent.core.pipeline import ScanOptions, scan, scrub
from pii_agent.core.profile_resolver import get_resolver, resolve_profile
from pii_agent.models.enums import Destination, ScrubAction
from pii_agent.profiles.schema import ProfileValidationError
from pii_agent.session.context import SessionContext
from pii_agent.utils.budgets import BudgetExceeded, Cancelled, ToolBudget, TurnBudget
from pii_agent.utils.content_gate import gate_result, gate_tool_output, sanitize_error
from pii_agent.utils.paths import PathRefused, list_scannable


class _SessionTool(BaseTool):
    """Base for tools bound to one session."""

    session: SessionContext
    budget: TurnBudget | None = None

    model_config = {"arbitrary_types_allowed": True}

    def _tool_budget(self) -> ToolBudget:
        return ToolBudget(turn=self.budget)

    def _fail(self, message: str, **extra: Any) -> str:
        payload: dict[str, Any] = {"status": "ERROR", "detail": message}
        payload.update(extra)
        return gate_tool_output(payload)

    def _run(self, **kwargs: Any) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


# ---------------------------------------------------------------------------
# list_sources
# ---------------------------------------------------------------------------
class ListSourcesInput(BaseModel):
    pattern: str = Field(
        default="*",
        description="Optional glob to filter filenames, e.g. '*.log'",
    )


class ListSourcesTool(_SessionTool):
    name: str = "list_sources"
    description: str = (
        "List what can be scanned: files within the operator-configured scan "
        "roots, plus anything already loaded this session such as an upload or "
        "pasted text. Returns names and sizes. Use this when the user asks what "
        "is available, or refers to a file without giving a full path. Pass the "
        "name straight to scan."
    )
    args_schema: type[BaseModel] = ListSourcesInput

    def _run(self, pattern: str = "*") -> str:
        try:
            found = list_scannable(self.session.settings, pattern)
        except Exception as exc:
            return self._fail(sanitize_error(exc))

        # Uploads and pastes live in memory with no path, so they never appear in
        # a filesystem listing. Omitting them made an uploaded file look absent.
        loaded = [
            {
                "name": str(r.metadata.get("display_name", "")) or "loaded content",
                "size_mb": round(r.bytes_total / 1048576, 3),
                "type": str(r.metadata.get("extension", "")),
                "origin": "loaded in this session",
            }
            for r in self.session.content_store.loaded_sources()
            if r.metadata.get("display_name")
        ]

        files = [
            {
                "name": f.display_path,
                "size_mb": f.size_mb,
                "type": f.extension,
                "origin": "scan root",
            }
            for f in found[:100]
        ]

        if not files and not loaded:
            roots = len(self.session.settings.scan_roots)
            return gate_tool_output(
                {
                    "status": "OK",
                    "count": 0,
                    "detail": (
                        "No scannable files found."
                        if roots
                        else "No scan roots are configured, so only uploaded "
                        "files can be scanned."
                    ),
                }
            )

        return gate_tool_output(
            {
                "status": "OK",
                "count": len(files) + len(loaded),
                "files": [*loaded, *files],
                "truncated": len(found) > 100,
            }
        )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
class ScanInput(BaseModel):
    source: str = Field(
        description=(
            "A file path within a configured scan root, or an existing content "
            "handle from a previous step."
        )
    )
    profile: str | None = Field(
        default=None,
        description=(
            "Scrub profile, e.g. DEFAULT_PII or HEALTHCARE. Omit to use the "
            "session preference."
        ),
    )
    destination: str | None = Field(
        default=None,
        description=(
            "Where the cleaned data is going: INTERNAL_SIEM, EXTERNAL_ANALYTICS, "
            "EXTERNAL_LLM, FILE, or S3. Some entity types are handled "
            "differently depending on this."
        ),
    )


class ScanTool(_SessionTool):
    name: str = "scan"
    description: str = (
        "Detect sensitive data in a file or in previously loaded content. "
        "Returns counts by entity type, severity breakdown, coverage, and a "
        "content handle — never the content itself and never character "
        "positions. Does not modify anything."
    )
    args_schema: type[BaseModel] = ScanInput

    def _run(
        self,
        source: str,
        profile: str | None = None,
        destination: str | None = None,
    ) -> str:
        tool_budget = self._tool_budget()
        try:
            tool_budget.check()
            handle = _resolve_source(source, self.session)
            options = _build_options(self.session, profile, destination)
            result = scan(handle, self.session, options)
        except (PathRefused, ProfileValidationError) as exc:
            return self._fail(sanitize_error(exc))
        except (BudgetExceeded, Cancelled) as exc:
            return self._fail(sanitize_error(exc))
        except Exception as exc:
            return self._fail(sanitize_error(exc))

        _remember_scan(self.session, result.content_handle)
        # The UI renders from here, not from the model's reply: the findings
        # table and any download must reflect the result itself rather than a
        # paraphrase of it.
        self.session.record_result(result)

        payload = gate_result(result)
        # A scan produces no artifact by definition, so artifact_available is
        # always false here. Left unexplained, that reads as a denial: the agent
        # reported a clean copy as impossible and invented a cause, when it had
        # simply not called scrub yet.
        if not result.refusal:
            payload["next_step"] = (
                "This is a report only — scanning never produces a cleaned copy, "
                "and nothing was refused. Call scrub with the same source to "
                "create one."
            )
        return gate_tool_output(payload)


# ---------------------------------------------------------------------------
# scrub
# ---------------------------------------------------------------------------
class ScrubInput(BaseModel):
    content_handle: str = Field(
        description="Handle returned by a previous scan, or a file path to scan first."
    )
    profile: str | None = Field(default=None, description="Optional profile override.")
    destination: str | None = Field(
        default=None, description="Where the cleaned data is going."
    )
    requested_action: str | None = Field(
        default=None,
        description=(
            "Optional stricter handling the user asked for, e.g. REDACT. This is "
            "a REQUEST: policy may override it with something more restrictive, "
            "and it is discarded if weaker than the profile requires. It cannot "
            "be used to reduce protection."
        ),
    )
    dry_run: bool = Field(
        default=False,
        description="Resolve policy and report what would happen, changing nothing.",
    )


class ScrubTool(_SessionTool):
    name: str = "scrub"
    description: str = (
        "Produce a cleaned copy of previously scanned content, applying the "
        "policy-resolved action to each detected entity. Refuses and explains "
        "when coverage was incomplete, when policy blocks the artifact, or when "
        "verification finds anything left over. Returns a summary and a handle "
        "to the cleaned output."
    )
    args_schema: type[BaseModel] = ScrubInput

    def _run(
        self,
        content_handle: str,
        profile: str | None = None,
        destination: str | None = None,
        requested_action: str | None = None,
        dry_run: bool = False,
    ) -> str:
        tool_budget = self._tool_budget()
        try:
            tool_budget.check()
            handle = _resolve_source(content_handle, self.session)
            options = _build_options(
                self.session, profile, destination, requested_action, dry_run
            )
            result = scrub(handle, self.session, options)
        except (PathRefused, ProfileValidationError) as exc:
            return self._fail(sanitize_error(exc))
        except (BudgetExceeded, Cancelled) as exc:
            return self._fail(sanitize_error(exc))
        except ValueError as exc:
            return self._fail(sanitize_error(exc))
        except Exception as exc:
            return self._fail(sanitize_error(exc))

        if result.sanitized_handle:
            self.session.preferences["_last_sanitized"] = result.sanitized_handle

        # Published for the UI. Without this the cleaned copy exists only as a
        # handle inside the ContentStore and there is no way for the user to
        # reach it: the download button had nothing to render from, so a
        # successful scrub produced no visible output.
        self.session.record_result(result)

        return gate_tool_output(gate_result(result))


# ---------------------------------------------------------------------------
# explain_profile
# ---------------------------------------------------------------------------
class ExplainProfileInput(BaseModel):
    profile: str = Field(description="Profile name to describe.")


class ExplainProfileTool(_SessionTool):
    name: str = "explain_profile"
    description: str = (
        "Describe what a scrub profile detects and what it does with each entity "
        "type. Use when the user asks what a profile covers, or to confirm a "
        "profile choice before scanning."
    )
    args_schema: type[BaseModel] = ExplainProfileInput

    def _run(self, profile: str) -> str:
        try:
            effective = resolve_profile(profile)
        except ProfileValidationError as exc:
            return self._fail(
                sanitize_error(exc),
                available=list(get_resolver().available_profiles()),
            )

        return gate_tool_output(
            {
                "status": "OK",
                "profile": effective.name,
                "version": effective.version,
                "inheritance": list(effective.applied_profiles),
                "required_detectors": sorted(effective.required_detectors),
                "entity_count": len(effective.enabled_types),
                "entities": [
                    {
                        "type": entity_type,
                        "action": effective.action_for(entity_type).value,
                        "varies_by_destination": entity_type
                        in effective.destination_sensitive_types,
                    }
                    for entity_type in effective.enabled_types
                ],
            }
        )


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------
class ExportInput(BaseModel):
    sanitized_handle: str = Field(
        description="Handle to cleaned output returned by scrub."
    )


class ExportTool(_SessionTool):
    name: str = "export"
    description: str = (
        "Confirm that a cleaned artifact is available for the user to download. "
        "Only works for output that passed verification."
    )
    args_schema: type[BaseModel] = ExportInput

    def _run(self, sanitized_handle: str) -> str:
        try:
            record = self.session.content_store.get(sanitized_handle)
        except KeyError:
            return self._fail(
                "that handle is not recognised in this session. Run scrub first."
            )

        if not record.is_sanitized:
            return self._fail(
                "that handle refers to original content, not a cleaned copy. "
                "Only verified cleaned output can be exported."
            )

        return gate_tool_output(
            {
                "status": "OK",
                "handle": sanitized_handle,
                "size_bytes": record.bytes_total,
                "profile": record.profile_name,
                "detail": "The cleaned copy is ready for download.",
            }
        )


# ---------------------------------------------------------------------------
# set_preference
# ---------------------------------------------------------------------------
class SetPreferenceInput(BaseModel):
    key: str = Field(
        description=(
            "One of: profile, confidence_threshold, destination, locale, "
            "requested_action"
        )
    )
    value: str = Field(description="The value to record.")


class SetPreferenceTool(_SessionTool):
    name: str = "set_preference"
    description: str = (
        "Record a preference for this session so the user does not have to "
        "repeat it: profile, confidence_threshold, destination, locale, or "
        "requested_action."
    )
    args_schema: type[BaseModel] = SetPreferenceInput

    _ALLOWED = frozenset(
        {
            "profile",
            "confidence_threshold",
            "destination",
            "locale",
            "requested_action",
        }
    )

    def _run(self, key: str, value: str) -> str:
        normalised = key.strip().lower()
        if normalised not in self._ALLOWED:
            return self._fail(
                f"'{key}' is not a settable preference. Options: "
                f"{', '.join(sorted(self._ALLOWED))}"
            )

        try:
            stored = _coerce_preference(normalised, value)
        except ValueError as exc:
            return self._fail(str(exc))

        self.session.preferences[normalised] = stored
        return gate_tool_output(
            {
                "status": "OK",
                "key": normalised,
                "recorded": str(stored),
                "detail": f"I'll use {normalised}={stored} for this session.",
            }
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _resolve_source(source: str, session: SessionContext) -> str:
    """Accept either an existing handle or a path, returning a handle.

    Letting the agent pass a path directly avoids a mandatory extra hop, which
    is one fewer chance for it to drop a parameter.
    """
    candidate = source.strip()
    if session.content_store.exists(candidate):
        return candidate

    # A bare filename may name something already in memory — an upload or a
    # paste, which has no path in a scan root. Only bare names are considered:
    # anything with a separator is an explicit filesystem request and must go
    # through containment, so a label can never shadow a path.
    if not _has_path_separator(candidate):
        existing = session.content_store.find_by_label(candidate)
        if existing is not None:
            return existing.handle

    return load_file(candidate, session).handle


def _has_path_separator(candidate: str) -> bool:
    """True when the string is shaped like a path rather than a bare name."""
    return "/" in candidate or "\\" in candidate or ":" in candidate


def _build_options(
    session: SessionContext,
    profile: str | None,
    destination: str | None,
    requested_action: str | None = None,
    dry_run: bool = False,
) -> ScanOptions:
    prefs = session.preferences
    profile_name = (profile or prefs.get("profile") or "DEFAULT_PII").strip().upper()

    dest_raw = destination or prefs.get("destination")
    dest = _coerce_destination(dest_raw) if dest_raw else None

    action_raw = requested_action or prefs.get("requested_action")
    action = _coerce_action(action_raw) if action_raw else None

    threshold = prefs.get("confidence_threshold")

    return ScanOptions(
        profile_names=(profile_name,),
        destination=dest,
        requested_action=action,
        confidence_threshold=threshold,
        dry_run=dry_run,
    )


def _coerce_destination(value: Any) -> Destination:
    if isinstance(value, Destination):
        return value
    try:
        return Destination(str(value).strip().upper())
    except ValueError:
        valid = ", ".join(d.value for d in Destination)
        raise ValueError(f"unknown destination '{value}'. Valid: {valid}") from None


def _coerce_action(value: Any) -> ScrubAction:
    if isinstance(value, ScrubAction):
        return value
    try:
        return ScrubAction(str(value).strip().upper())
    except ValueError:
        valid = ", ".join(a.value for a in ScrubAction)
        raise ValueError(f"unknown action '{value}'. Valid: {valid}") from None


def _coerce_preference(key: str, value: str) -> Any:
    if key == "confidence_threshold":
        try:
            number = float(value)
        except ValueError:
            raise ValueError(
                f"confidence_threshold must be a number between 0.0 and 1.0, "
                f"got '{value}'"
            ) from None
        if not 0.0 <= number <= 1.0:
            raise ValueError(
                f"confidence_threshold must be between 0.0 and 1.0, got {number}"
            )
        return number

    if key == "destination":
        return _coerce_destination(value).value

    if key == "requested_action":
        return _coerce_action(value).value

    if key == "profile":
        name = value.strip().upper()
        # Validate now so a bad profile fails at the point the user set it,
        # rather than confusingly on the next scan.
        resolve_profile(name)
        return name

    return value.strip()


def _remember_scan(session: SessionContext, handle: str) -> None:
    scanned = session.preferences.setdefault("_scanned_handles", [])
    if handle not in scanned:
        scanned.append(handle)
    session.preferences["_last_scan"] = handle
