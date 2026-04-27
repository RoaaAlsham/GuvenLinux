# Contributing to LinuxGuard

Thank you for your interest in contributing to LinuxGuard! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/linuxguard.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Set up the development environment (see below)

## Development Environment

### Prerequisites

- Debian-based Linux distribution
- Python 3.10+
- GTK4 development libraries

### Setup

```bash
# Install system dependencies
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 libgtk-4-dev

# Install Python dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v
```

## Code Standards

- Follow **PEP 8** style guidelines
- Use **type hints** for all function signatures
- Write **docstrings** for all public modules, classes, and functions
- Keep line length under 100 characters

## Commit Messages

Use clear, descriptive commit messages:

```
<type>: <short description>

<optional longer description>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`

Example:
```
feat: add SSH cipher validation to ssh_auditor engine

Check for weak ciphers (3des-cbc, arcfour) and flag them as
High severity findings with recommended replacements.
```

## Pull Request Process

1. Ensure all tests pass: `pytest tests/ -v`
2. Ensure code passes linting: `flake8 src/ tests/`
3. Update documentation if your change affects user-facing behavior
4. Fill out the pull request template completely
5. Request review from at least one maintainer

## Testing

- Write unit tests for all new engine logic
- Use `pytest` fixtures and mocks for system calls
- Target **85%+ code coverage** on new code
- Run the full suite before submitting: `pytest tests/ -v --cov=src`

## Reporting Bugs

Open an issue using the **Bug Report** template and include:

- OS version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output

## Feature Requests

Open an issue using the **Feature Request** template. Describe:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 License.
