"""
Pytest configuration - Simplified for standalone detector testing
"""
import pytest
import sys
from pathlib import Path

# Add project root to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))


@pytest.fixture
def mock_scan_response():
    """Mock HTTP response for scan testing"""
    class MockResponse:
        def __init__(self, status_code=200, text='', headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.content = text.encode()

        def json(self):
            import json
            return json.loads(self.text)

    return MockResponse
