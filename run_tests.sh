#!/bin/bash

# BugBounty Arsenal - Testing Quick Start Script
# Run this to execute all tests and generate coverage report

echo "🧪 BugBounty Arsenal - Test Suite"
echo "=================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in Docker or local
if [ -f /.dockerenv ]; then
    echo "📦 Running inside Docker container"
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    echo "💻 Running locally"
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
fi

echo ""

# Step 1: Install dependencies
echo -e "${YELLOW}Step 1: Installing test dependencies...${NC}"
$PIP_CMD install -q pytest pytest-django pytest-asyncio pytest-cov pytest-mock faker factory-boy
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Step 2: Run linting
echo -e "${YELLOW}Step 2: Running code quality checks...${NC}"
if command -v flake8 &> /dev/null; then
    echo "  → Running flake8..."
    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true
    echo -e "${GREEN}✓ Linting completed${NC}"
else
    echo -e "${YELLOW}⚠ flake8 not installed, skipping${NC}"
fi
echo ""

# Step 3: Run migrations
echo -e "${YELLOW}Step 3: Running database migrations...${NC}"
$PYTHON_CMD manage.py migrate --noinput
echo -e "${GREEN}✓ Migrations applied${NC}"
echo ""

# Step 4: Create test data
echo -e "${YELLOW}Step 4: Creating test data...${NC}"
$PYTHON_CMD manage.py populate_scan_categories || true
echo -e "${GREEN}✓ Test data created${NC}"
echo ""

# Step 5: Run tests
echo -e "${YELLOW}Step 5: Running test suite...${NC}"
echo ""

# Run with coverage
pytest -v \
    --cov=. \
    --cov-report=html \
    --cov-report=term-missing \
    --cov-report=xml \
    --tb=short \
    -p no:warnings

TEST_EXIT_CODE=$?

echo ""

# Step 6: Generate coverage summary
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    echo "📊 Coverage Report:"
    echo "  → HTML Report: htmlcov/index.html"
    echo "  → XML Report: coverage.xml"
    echo ""
    echo "To view HTML coverage report:"
    echo "  python -m http.server 8080 --directory htmlcov"
    echo "  Then open: http://localhost:8080"
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo "Check the output above for details"
fi

echo ""
echo "=================================="
echo "🎉 Testing complete!"
echo ""

exit $TEST_EXIT_CODE
