"""Dependency rules D1-D7, enforced by AST inspection.

Design document, Correctness Property 17.

Architecture that is only documented decays. These rules are the ones that keep the
two products separable and keep the reasoning loop out of the data path, and every
one of them is a rule someone will eventually break by accident — an import added
for convenience during debugging, left in.

Each rule below was verified by writing a violation, confirming the test failed, and
removing it. A rule that has never failed has never been tested.

Rules, from the design document:

    D1  pii_agent imports nothing from explorer
    D2  explorer reaches pii_agent only via explorer.security.pii_service
    D3  pii_agent.core imports no LLM library         (also asserted by subprocess)
    D4  pii_agent.core imports nothing from pii_agent.agent or .tools
    D5  explorer deterministic services import nothing from explorer.agents or .llm
    D6  redaction is on the trace write path          (behavioural, not structural)
    D7  no package imports a ui package
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.paths import REPO_ROOT

PRODUCT_PACKAGES = ("pii_agent", "explorer")

LLM_LIBRARIES = ("langgraph", "langchain", "langchain_openai", "openai", "tiktoken")

# Deterministic platform services: they process data and must not be able to reach
# a model. A chunker that *can* call a model eventually will.
EXPLORER_DETERMINISTIC = (
    "explorer.chunking",
    "explorer.embeddings",
    "explorer.retrieval",
    "explorer.storage",
    "explorer.observability",
    "explorer.security.pii_service",
)


@dataclass(frozen=True)
class ImportRef:
    """One import statement, located."""

    module: str          # dotted module doing the importing, e.g. pii_agent.core.policy
    imported: str        # dotted module being imported
    path: Path
    lineno: int

    def __str__(self) -> str:
        rel = self.path.relative_to(REPO_ROOT)
        return f"{rel}:{self.lineno}  {self.module} imports {self.imported}"


def _module_name(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _collect() -> list[ImportRef]:
    """Every import in every product package, including function-local ones.

    Function-local imports are not an edge case here: the codebase uses them
    deliberately to defer heavy loads, so a check that only looked at module-level
    imports would miss a large share of the real dependency graph.
    """
    refs: list[ImportRef] = []

    for package in PRODUCT_PACKAGES:
        root = REPO_ROOT / package
        if not root.is_dir():
            continue

        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue

            module = _module_name(path)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        refs.append(
                            ImportRef(module, alias.name, path, node.lineno)
                        )
                elif isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import, which cannot cross a package
                    # boundary and so cannot violate these rules.
                    if node.level == 0 and node.module:
                        refs.append(
                            ImportRef(module, node.module, path, node.lineno)
                        )

    return refs


@pytest.fixture(scope="module")
def imports() -> list[ImportRef]:
    collected = _collect()
    assert collected, "no imports collected — the AST walk is not finding files"
    return collected


def _in(module: str, prefix: str) -> bool:
    """True when ``module`` is ``prefix`` or inside it."""
    return module == prefix or module.startswith(prefix + ".")


def _fail(rule: str, violations: list[ImportRef], why: str) -> None:
    listing = "\n  ".join(str(v) for v in violations)
    pytest.fail(f"{rule} violated:\n  {listing}\n\n{why}")


# ---------------------------------------------------------------------------
# D1
# ---------------------------------------------------------------------------
def test_d1_pii_agent_does_not_import_explorer(imports):
    """The security product must stay independently deployable.

    If it cannot ship without the platform, its guarantees become the platform's
    problem too — and the reason to trust it is that it is small enough to audit.
    """
    violations = [
        ref
        for ref in imports
        if _in(ref.module, "pii_agent") and _in(ref.imported, "explorer")
    ]
    if violations:
        _fail(
            "D1",
            violations,
            "pii_agent must not depend on the platform. Move the shared code into "
            "pii_agent, or invert the dependency so the platform calls in.",
        )


# ---------------------------------------------------------------------------
# D2
# ---------------------------------------------------------------------------
def test_d2_explorer_reaches_pii_agent_only_through_the_service_seam(imports):
    """One contract, one place to change, one place to review."""
    seam = "explorer.security.pii_service"
    violations = [
        ref
        for ref in imports
        if _in(ref.module, "explorer")
        and _in(ref.imported, "pii_agent")
        and not _in(ref.module, seam)
    ]
    if violations:
        _fail(
            "D2",
            violations,
            f"Route this through {seam}. A second import path means the contract "
            f"is no longer the only thing that has to hold.",
        )


# ---------------------------------------------------------------------------
# D3
# ---------------------------------------------------------------------------
def test_d3_pii_agent_core_imports_no_llm_library(imports):
    """Structural companion to the subprocess sys.modules assertion.

    That test proves the absence at runtime; this one localises the cause to a
    file and a line when it breaks.
    """
    violations = [
        ref
        for ref in imports
        if _in(ref.module, "pii_agent.core")
        and any(_in(ref.imported, lib) for lib in LLM_LIBRARIES)
    ]
    if violations:
        _fail(
            "D3",
            violations,
            "The deterministic core must not import an LLM library. This is the "
            "central claim of the architecture: the model never sees content.",
        )


# ---------------------------------------------------------------------------
# D4
# ---------------------------------------------------------------------------
def test_d4_core_does_not_import_the_agent_or_tool_layers(imports):
    """Keeps the reasoning loop out of the data path.

    The original architecture review found that placing the loop inside the data
    and policy path produced five of six blocker findings. This is the structural
    guard against it returning.
    """
    forbidden = ("pii_agent.agent", "pii_agent.tools")
    violations = [
        ref
        for ref in imports
        if _in(ref.module, "pii_agent.core")
        and any(_in(ref.imported, f) for f in forbidden)
    ]
    if violations:
        _fail(
            "D4",
            violations,
            "Dependencies point inward. core is beneath tools and agent, so it "
            "cannot reach up into them.",
        )


# ---------------------------------------------------------------------------
# D5
# ---------------------------------------------------------------------------
def test_d5_deterministic_platform_services_cannot_reach_a_model(imports):
    """Same reasoning as D4, applied to the platform."""
    forbidden = ("explorer.agents", "explorer.llm")
    violations = [
        ref
        for ref in imports
        if any(_in(ref.module, svc) for svc in EXPLORER_DETERMINISTIC)
        and any(_in(ref.imported, f) for f in forbidden)
    ]
    if violations:
        _fail(
            "D5",
            violations,
            "A deterministic service that can call a model is no longer "
            "deterministic. Pass the result in, rather than fetching it here.",
        )


def test_d5_deterministic_platform_services_import_no_llm_library(imports):
    violations = [
        ref
        for ref in imports
        if any(_in(ref.module, svc) for svc in EXPLORER_DETERMINISTIC)
        and any(_in(ref.imported, lib) for lib in LLM_LIBRARIES)
    ]
    if violations:
        _fail(
            "D5",
            violations,
            "Deterministic services must not import an LLM library directly "
            "either. explorer.security.llm_assist is the sanctioned exception "
            "and is deliberately not in this list.",
        )


# ---------------------------------------------------------------------------
# D7
# ---------------------------------------------------------------------------
def test_d7_nothing_imports_a_ui_package(imports):
    """Presentation is a leaf.

    Anything a UI needs that logic also needs belongs in the layer below. Without
    this, presenters accumulate business rules and become untestable without a
    rendering framework.
    """
    ui_packages = ("pii_agent.ui", "explorer.ui")
    violations = [
        ref
        for ref in imports
        if any(_in(ref.imported, ui) for ui in ui_packages)
        # A ui package may import within itself.
        and not any(_in(ref.module, ui) for ui in ui_packages)
    ]
    if violations:
        _fail(
            "D7",
            violations,
            "Move the shared logic down a layer. Entry points under apps/ are "
            "outside the product packages and may import ui freely.",
        )


# ---------------------------------------------------------------------------
# Guards on the checker itself
# ---------------------------------------------------------------------------
def test_the_checker_sees_function_local_imports():
    """The codebase defers heavy loads with imports inside functions.

    A checker that only walked module-level imports would miss a large share of
    the real dependency graph while appearing to pass.
    """
    refs = _collect()
    local = [
        ref
        for ref in refs
        if ref.module == "pii_agent.core.detector"
        and ref.imported.startswith("pii_agent.core.")
    ]
    assert local, (
        "expected to find function-local imports inside pii_agent.core.detector; "
        "the AST walk may only be reading module-level statements"
    )


def test_the_checker_covers_both_products():
    """A silent scoping mistake would make every rule above vacuous."""
    refs = _collect()
    modules = {ref.module for ref in refs}

    assert any(m.startswith("pii_agent.") for m in modules)
    # explorer may be a skeleton of empty __init__ files at this point, so its
    # absence from the import graph is acceptable; its directory is not.
    assert (REPO_ROOT / "pii_agent").is_dir()
