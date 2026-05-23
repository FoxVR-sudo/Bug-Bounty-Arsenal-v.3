import pytest


class _FakeProcess:
    def __init__(self, stdout: bytes):
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""


@pytest.mark.detector
@pytest.mark.asyncio
async def test_katana_detector_aggregates_interesting_endpoints(monkeypatch):
    from detectors.katana_detector import katana_detector

    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProcess(
            b"\n".join(
                [
                    b"https://example.com/",
                    b"https://example.com/admin",
                    b"https://example.com/api/v1/users",
                    b"https://example.com/login",
                ]
            )
        )

    monkeypatch.setattr("detectors.katana_detector.shutil.which", lambda _: "/usr/bin/katana")
    monkeypatch.setattr(
        "detectors.katana_detector.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    findings = await katana_detector(session=None, url="https://example.com", context={})

    assert len(findings) == 2
    assert findings[0]["type"] == "Web Crawl Summary"
    assert findings[0]["severity"] == "info"
    assert findings[1]["type"] == "Interesting Endpoints Discovered"
    assert findings[1]["severity"] == "info"
    assert "https://example.com/admin" in findings[1]["evidence"]
    assert "https://example.com/api/v1/users" in findings[1]["evidence"]
    assert not any(f.get("severity") == "low" for f in findings)
