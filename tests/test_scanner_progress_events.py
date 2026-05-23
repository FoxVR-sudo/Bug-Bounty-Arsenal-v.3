import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_scan_single_url_emits_progress_events(monkeypatch):
    import scanner

    events = []

    def progress_cb(payload):
        events.append(payload)

    async def dummy_active(session, url, context):
        return []

    def dummy_passive(text, meta):
        return []

    # Ensure dummy detector is treated as allowed by tier filter.
    monkeypatch.setattr(scanner, "_detector_key_for_function", lambda name: "xss_pattern_detector")
    monkeypatch.setattr(scanner, "ACTIVE_DETECTORS", [dummy_active])
    monkeypatch.setattr(scanner, "PASSIVE_DETECTORS", [dummy_passive])

    # Avoid any real network / crawler / file IO.
    monkeypatch.setattr(scanner, "_fetch_with_timeout", AsyncMock(return_value=(200, "OK", {}, 0.01)))
    monkeypatch.setattr(scanner.crawler, "discover_params", AsyncMock(return_value={}))
    monkeypatch.setattr(scanner, "_save_raw_response", lambda *args, **kwargs: None)

    mock_session = MagicMock()
    mock_session.headers = {}

    context = {
        "timeout": 1,
        "allow_destructive": False,
        "output_dir": "raw_responses",
        "per_host_rate": 0.0,
        "scan_mode": "normal",
        "user_tier": "enterprise",
        "_progress_callback": progress_cb,
    }

    res = await scanner.scan_single_url(mock_session, "https://example.com", context)
    assert isinstance(res, dict)

    starts = [e for e in events if e.get("event") == "detector_start"]
    ends = [e for e in events if e.get("event") == "detector_end"]

    assert starts, "Expected at least one detector_start progress event"
    assert ends, "Expected at least one detector_end progress event"
    assert starts[0].get("url") == "https://example.com"
