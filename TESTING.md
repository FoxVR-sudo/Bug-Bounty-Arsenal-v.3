# 🧪 BugBounty Arsenal - Testing Guide

Comprehensive testing infrastructure for the BugBounty Arsenal platform.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Coverage Reports](#coverage-reports)
- [CI/CD Integration](#cicd-integration)

---

## 🚀 Quick Start

### Option 1: Using the Test Script (Recommended)

```bash
# Make script executable (first time only)
chmod +x run_tests.sh

# Run all tests
./run_tests.sh
```

### Option 2: Using Docker

```bash
# Run tests in Docker container
docker compose exec web pytest -v

# With coverage
docker compose exec web pytest --cov=. --cov-report=html -v
```

### Option 3: Local Development

```bash
# Install test dependencies
pip install pytest pytest-django pytest-asyncio pytest-cov pytest-mock

# Run tests
pytest -v

# With coverage
pytest --cov=. --cov-report=html --cov-report=term-missing -v
```

---

## 📁 Test Structure

```
tests/
├── __init__.py                    # Test package initialization
├── test_xss_detector.py           # XSS detector unit tests
├── test_sql_detector.py           # SQL injection detector tests
├── test_api_scans.py              # Scan API integration tests
├── test_api_auth.py               # Authentication API tests
└── test_api_subscriptions.py     # Subscription system tests

conftest.py                        # Shared pytest fixtures
pytest.ini                         # Pytest configuration
.coveragerc                        # Coverage configuration
```

---

## 🧪 Test Categories

### Unit Tests
Test individual components in isolation.

**Example: Detector Tests**
```python
@pytest.mark.detector
@pytest.mark.asyncio
async def test_xss_reflected_in_response(mock_scan_response):
    url = "https://example.com/search"
    findings = await detect(url, config)
    assert len(findings) > 0
```

### Integration Tests
Test API endpoints and database interactions.

**Example: API Tests**
```python
@pytest.mark.api
def test_create_scan_authenticated(authenticated_client, user_subscription):
    response = authenticated_client.post('/api/scans/', data)
    assert response.status_code == 201
```

---

## ▶️ Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test File
```bash
pytest tests/test_xss_detector.py
```

### Run Specific Test Class
```bash
pytest tests/test_api_scans.py::TestScanAPI
```

### Run Specific Test Function
```bash
pytest tests/test_api_scans.py::TestScanAPI::test_create_scan_authenticated
```

### Run Tests by Marker
```bash
# Run only detector tests
pytest -m detector

# Run only API tests
pytest -m api

# Run only integration tests
pytest -m integration
```

### Run with Verbose Output
```bash
pytest -v
```

### Run with Coverage
```bash
# Terminal output
pytest --cov=. --cov-report=term-missing

# HTML report
pytest --cov=. --cov-report=html

# Both
pytest --cov=. --cov-report=html --cov-report=term-missing
```

### Stop on First Failure
```bash
pytest -x
```

### Show Print Statements
```bash
pytest -s
```

---

## ✍️ Writing Tests

### Basic Test Structure

```python
import pytest
from myapp.models import MyModel


class TestMyFeature:
    """Test suite for my feature"""
    
    @pytest.mark.unit
    def test_simple_case(self):
        """Test description"""
        # Arrange
        data = "test"
        
        # Act
        result = process(data)
        
        # Assert
        assert result == "expected"
```

### Using Fixtures

```python
def test_with_user(test_user):
    """Test using the test_user fixture"""
    assert test_user.username == "testuser"
    assert test_user.is_verified is True
```

### Testing Async Functions

```python
@pytest.mark.asyncio
async def test_async_detector():
    """Test async detector function"""
    url = "https://example.com"
    findings = await detect(url, config={})
    assert isinstance(findings, list)
```

### Mocking External Calls

```python
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_with_mock():
    with patch('aiohttp.ClientSession.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html>test</html>')
        mock_get.return_value.__aenter__.return_value = mock_response
        
        # Your test code here
        findings = await detect(url, config)
        assert len(findings) == 0
```

---

## 📊 Available Fixtures

### User Fixtures
- `test_user` - Regular authenticated user
- `test_admin` - Admin/superuser
- `authenticated_client` - API client with auth

### Plan Fixtures
- `free_plan` - FREE subscription plan
- `pro_plan` - PRO subscription plan
- `enterprise_plan` - ENTERPRISE subscription plan

### Subscription Fixtures
- `user_subscription` - Active subscription for test user

### Category Fixtures
- `scan_categories` - All 6 scan categories
- `detector_configs` - Basic detector configurations

### Client Fixtures
- `api_client` - DRF API client
- `django_client` - Django test client

### Mock Fixtures
- `mock_scan_response` - Mock HTTP response

---

## 📈 Coverage Reports

### Generate HTML Report
```bash
pytest --cov=. --cov-report=html
```

View report:
```bash
# Start simple HTTP server
python -m http.server 8080 --directory htmlcov

# Open in browser
# http://localhost:8080
```

### Generate Terminal Report
```bash
pytest --cov=. --cov-report=term-missing
```

### Generate XML Report (for CI/CD)
```bash
pytest --cov=. --cov-report=xml
```

### Coverage Configuration

Edit `.coveragerc` to customize:
```ini
[run]
omit = 
    */migrations/*
    */tests/*
    */__pycache__/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
```

---

## 🔄 CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Every push to `master` or `develop`
- Every pull request

**Workflow:** `.github/workflows/ci.yml`

**What it tests:**
- ✅ Python 3.11 and 3.12
- ✅ PostgreSQL database
- ✅ Redis cache
- ✅ Code linting (flake8, black, isort)
- ✅ Unit and integration tests
- ✅ Code coverage
- ✅ Frontend build
- ✅ Security scanning

View results:
1. Go to GitHub repository
2. Click "Actions" tab
3. See test results for each commit

---

## 🐛 Debugging Tests

### Run with Debugging
```bash
# Show full traceback
pytest --tb=long

# Drop into debugger on failure
pytest --pdb

# Show local variables
pytest -l
```

### Common Issues

#### "No module named X"
```bash
# Install test dependencies
pip install -r requirements.txt
```

#### "Database not found"
```bash
# Run migrations
python manage.py migrate
```

#### "Permission denied"
```bash
# Make test script executable
chmod +x run_tests.sh
```

#### "Fixture not found"
```bash
# Ensure conftest.py is in the right location
# It should be in the project root
```

---

## 📝 Test Markers

Available test markers (defined in `pytest.ini`):

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.detector` - Detector tests
- `@pytest.mark.api` - API endpoint tests
- `@pytest.mark.selenium` - Browser tests (if added)

Usage:
```python
@pytest.mark.detector
@pytest.mark.slow
async def test_comprehensive_scan():
    # Test code
    pass
```

Run specific markers:
```bash
pytest -m "detector and not slow"
```

---

## 🎯 Coverage Goals

| Component | Target Coverage | Current Status |
|-----------|----------------|----------------|
| Models | 90%+ | ⚪ TBD |
| Views/APIs | 85%+ | ⚪ TBD |
| Detectors | 80%+ | ⚪ TBD |
| Utilities | 90%+ | ⚪ TBD |
| Overall | 80%+ | ⚪ TBD |

---

## 🔧 Advanced Usage

### Parallel Testing
```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel
pytest -n auto
```

### Test Only Changed Files
```bash
# Install pytest-testmon
pip install pytest-testmon

# Run only affected tests
pytest --testmon
```

### Generate HTML Test Report
```bash
# Install pytest-html
pip install pytest-html

# Generate report
pytest --html=report.html --self-contained-html
```

---

## 📚 Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Django Testing](https://docs.djangoproject.com/en/stable/topics/testing/)
- [DRF Testing](https://www.django-rest-framework.org/api-guide/testing/)
- [Coverage.py](https://coverage.readthedocs.io/)

---

## 💡 Best Practices

1. **Write tests first** (TDD approach when possible)
2. **Test one thing at a time**
3. **Use descriptive test names**
4. **Keep tests independent**
5. **Mock external dependencies**
6. **Maintain >80% coverage**
7. **Run tests before committing**
8. **Fix failing tests immediately**

---

## 🆘 Need Help?

If tests are failing:

1. Check the error message carefully
2. Review the test code
3. Check fixture setup
4. Verify database state
5. Look at logs: `logs/` directory
6. Run with `-v` for verbose output
7. Use `--pdb` to debug

---

**Happy Testing! 🧪**
