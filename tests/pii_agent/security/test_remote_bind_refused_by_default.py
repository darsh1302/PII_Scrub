"""Guardrail G10, Requirement 44 — deployment exposure.

This service reads the local filesystem and pulls CloudWatch logs with the
host's credentials and has no authentication of its own. On a non-loopback bind
that access is available to any network peer, so startup must refuse.
"""

from __future__ import annotations

import pytest

from pii_agent.utils.config import ConfigError, Settings
from pii_agent.utils.startup import require_valid_startup, validate_startup


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(
        openai_api_key="sk-test",
        token_vault_salt=b"salt",
        scan_roots=(),
        bind_address="127.0.0.1",
        allow_remote=False,
        audit_dir=tmp_path / "audit",
    )
    base.update(overrides)
    return Settings(**base)


def test_loopback_bind_is_accepted(tmp_path):
    report = validate_startup(_settings(tmp_path), sweep=False)
    assert report.ok is True


@pytest.mark.parametrize(
    "address", ["0.0.0.0", "192.168.1.10", "10.0.0.5", "::", "example.internal"]
)
def test_non_loopback_bind_refused_without_explicit_flag(tmp_path, address):
    report = validate_startup(
        _settings(tmp_path, bind_address=address), sweep=False
    )
    assert report.ok is False
    assert any("not loopback" in e for e in report.errors)


def test_non_loopback_permitted_with_explicit_flag_but_warns(tmp_path):
    """Opting in is allowed, but must not be silent."""
    report = validate_startup(
        _settings(tmp_path, bind_address="0.0.0.0", allow_remote=True),
        sweep=False,
    )
    assert report.ok is True
    assert any("reverse proxy" in w for w in report.warnings)


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "localhost", "127.0.0.53"])
def test_loopback_forms_recognised(tmp_path, address):
    report = validate_startup(
        _settings(tmp_path, bind_address=address), sweep=False
    )
    assert report.ok is True


def test_missing_openai_key_blocks_startup(tmp_path):
    report = validate_startup(_settings(tmp_path, openai_api_key=""), sweep=False)
    assert report.ok is False
    assert any("OPENAI_API_KEY" in e for e in report.errors)


def test_require_valid_startup_raises_on_unsafe_config(tmp_path):
    with pytest.raises(ConfigError) as exc:
        require_valid_startup(_settings(tmp_path, bind_address="0.0.0.0"))
    assert "not loopback" in str(exc.value)


def test_missing_salt_warns_but_does_not_block(tmp_path):
    report = validate_startup(
        _settings(tmp_path, token_vault_salt=b""), sweep=False
    )
    assert report.ok is True
    assert any("SALT" in w or "salt" in w for w in report.warnings)


def test_scan_root_that_is_a_file_is_an_error(tmp_path):
    bogus = tmp_path / "not_a_dir.txt"
    bogus.write_text("x", encoding="utf-8")
    report = validate_startup(
        _settings(tmp_path, scan_roots=(bogus,)), sweep=False
    )
    assert report.ok is False
    assert any("not a directory" in e for e in report.errors)


def test_empty_scan_roots_warns_uploads_only(tmp_path):
    """Empty allowlist must mean 'uploads only', never 'whole filesystem'."""
    report = validate_startup(_settings(tmp_path, scan_roots=()), sweep=False)
    assert report.ok is True
    assert any("SCAN_ROOTS" in w for w in report.warnings)


def test_settings_repr_does_not_leak_secrets(tmp_path):
    s = _settings(
        tmp_path, openai_api_key="sk-super-secret-value", token_vault_salt=b"pepper"
    )
    rendered = repr(s)
    assert "sk-super-secret-value" not in rendered
    assert "pepper" not in rendered


# ---------------------------------------------------------------------------
# Placeholder-secret detection
#
# A non-empty template value passes a naive truthiness check and then fails
# later as an opaque 401. Catching it at startup turns a confusing runtime
# error into an actionable configuration message.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placeholder",
    [
        "your-api-key-here",
        "YOUR_API_KEY",
        "sk-...",
        "sk-xxxxxxxx",
        "changeme",
        "replace-me",
        "placeholder",
        "TODO",
        "<your-key>",
    ],
)
def test_placeholder_openai_key_blocks_startup(tmp_path, placeholder):
    report = validate_startup(
        _settings(tmp_path, openai_api_key=placeholder), sweep=False
    )
    assert report.ok is False
    assert any("placeholder" in e.lower() for e in report.errors)


def test_realistic_key_shape_is_accepted(tmp_path):
    """A real high-entropy key must never be flagged as a placeholder."""
    report = validate_startup(
        _settings(
            tmp_path,
            openai_api_key="sk-proj-9fK2mQ7xR4tZ8vB1nH6jL0pW3sD5gY2c",
        ),
        sweep=False,
    )
    assert report.ok is True


def test_placeholder_salt_blocks_startup(tmp_path):
    """A predictable salt defeats salting — precomputed tables become viable."""
    report = validate_startup(
        _settings(tmp_path, token_vault_salt=b"changeme"), sweep=False
    )
    assert report.ok is False
    assert any("salt" in e.lower() for e in report.errors)


def test_short_salt_warns(tmp_path):
    report = validate_startup(
        _settings(tmp_path, token_vault_salt=b"abc123"), sweep=False
    )
    assert report.ok is True
    assert any("short" in w.lower() for w in report.warnings)


def test_error_messages_never_contain_the_secret_value(tmp_path):
    """Validation must describe the problem without echoing the value."""
    secret = "your-api-key-here-abc123unique"
    report = validate_startup(
        _settings(tmp_path, openai_api_key=secret), sweep=False
    )
    assert report.ok is False
    assert secret not in report.summary()
