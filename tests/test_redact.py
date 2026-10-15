from __future__ import annotations

import pytest

from mcpmonitor.redact import redact_env, redact_labels, redact_text, shape_logs


def test_redact_env_hides_secret_keys_only():
    out = redact_env(["TZ=UTC", "SONARR_API_KEY=abc", "PASSWORD=x", "NOEQUALS"])
    assert out == ["TZ=UTC", "SONARR_API_KEY=***", "PASSWORD=***", "NOEQUALS"]


def test_redact_env_scrubs_credentials_in_urls():
    assert redact_env(["DB=postgres://user:pw@db/x"]) == ["DB=postgres://user:***@db/x"]


def test_redact_labels():
    assert redact_labels({"app": "x", "api_key": "y"}) == {"app": "x", "api_key": "***"}


@pytest.mark.parametrize(
    "line,secret",
    [
        ("Authorization: Bearer abcdefghijklmnop1234", "abcdefghijklmnop1234"),
        ("token=sup3rs3cret value", "sup3rs3cret"),
        ("password: 'hunter2'", "hunter2"),
        ("using dh_" + "A" * 43, "A" * 43),
        ("https://discord.com/api/webhooks/123456/AbCdEf_ghIJ-klmn", "AbCdEf_ghIJ-klmn"),
        ("ghp_" + "a" * 36, "a" * 36),
    ],
)
def test_redact_text(line, secret):
    assert secret not in redact_text(line)


def test_redact_text_leaves_normal_lines():
    line = "2026-10-15 INFO started worker 3 in 0.2s"
    assert redact_text(line) == line


def test_shape_logs_filters_and_counts():
    out = shape_logs("a ok\nb ERROR boom\nc ok\nd error again", pattern="error", max_lines=10, max_bytes=1000)
    assert out["logs"] == "b ERROR boom\nd error again"
    assert (out["lines_scanned"], out["lines_matched"], out["truncated"]) == (4, 2, False)
    assert "untrusted" in out["note"].lower()


def test_shape_logs_keeps_newest_lines():
    text = "\n".join(f"line {i}" for i in range(100))
    out = shape_logs(text, max_lines=5, max_bytes=10_000)
    assert out["logs"].splitlines() == [f"line {i}" for i in range(95, 100)]
    assert out["truncated"] is True


def test_shape_logs_byte_cap():
    text = "\n".join("x" * 50 for _ in range(100))
    out = shape_logs(text, max_lines=1000, max_bytes=500)
    assert len(out["logs"].encode()) <= 500 and out["truncated"] is True


def test_shape_logs_rejects_bad_patterns():
    with pytest.raises(ValueError):
        shape_logs("x", pattern="(", max_lines=1, max_bytes=10)
    with pytest.raises(ValueError):
        shape_logs("x", pattern="a" * 201, max_lines=1, max_bytes=10)
