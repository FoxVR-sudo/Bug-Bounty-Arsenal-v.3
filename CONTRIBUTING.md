# Contributing to BugBounty Arsenal

Thank you for considering contributing to BugBounty Arsenal! 🎯

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Scanner output/logs if relevant

### Suggesting Features

We welcome feature requests! Please open an issue with:
- Clear description of the feature
- Use case and benefits
- Potential implementation approach (optional)

### Contributing Code

1. **Fork the repository**
   ```bash
   git clone https://github.com/FoxVR-sudo/BugBounty-Arsenal.git
   cd BugBounty-Arsenal
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set up development environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Make your changes**
   - Follow existing code style
   - Add tests if applicable
   - Update documentation
   - Ensure all detectors follow the registry pattern

5. **Test your changes**
   ```bash
   python main.py --scope targets.csv --consent
   ```

6. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: Add new feature description"
   ```

7. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Use meaningful variable names
- Add docstrings to functions/classes
- Keep functions focused and small

### Detector Development

When creating a new detector:

1. Create file in `detectors/` directory
2. Use the `@register_active` or `@register_passive` decorator
3. Follow async/await patterns
4. Include proper error handling
5. Return findings in standard format

Example:
```python
from detectors.registry import register_active

@register_active
async def my_detector(url, session, config):
    """
    Description of what this detector does.
    
    Args:
        url: Target URL to test
        session: aiohttp ClientSession
        config: Scanner configuration
        
    Returns:
        List of findings dictionaries
    """
    findings = []
    
    # Your detection logic here
    
    return findings
```

### Commit Message Format

Use conventional commits:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `chore:` - Maintenance tasks

Examples:
```
feat: Add GraphQL injection detector
fix: Handle timeout errors in SSRF detector
docs: Update IDOR detector documentation
```

## Adding New Detectors

Popular detector ideas:
- GraphQL injection
- XXE (XML External Entity)
- Command injection
- SSTI (Server-Side Template Injection)
- Race condition detection
- Authentication bypass patterns
- API security issues

## Testing

Before submitting:
1. Test against safe targets (httpbin.org, your own test servers)
2. Verify reports are generated correctly
3. Check for false positives
4. Ensure rate limiting works properly

## Documentation

Update documentation for:
- New detectors (add to README.md detector table)
- New features (update Features section)
- Configuration changes (update command-line options)
- API changes (update relevant docs)

## Code Review Process

1. Automated checks will run on PR
2. Maintainer review
3. Address feedback
4. Merge after approval

## Questions?

- Open an issue for questions
- Check existing issues/PRs first
- Be respectful and constructive

## Security

If you discover a security vulnerability:
- **DO NOT** open a public issue
- Email: foxvr81@gmail.com
- Provide detailed information
- Allow time for fix before disclosure

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for helping make BugBounty Arsenal better! 🚀**
