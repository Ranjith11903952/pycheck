# PyCheck 🔐

> A powerful CLI security scanner that detects hardcoded secrets, API keys, passwords, and sensitive data in your configuration files.

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)](https://github.com/Ranjith11903952/pycheck)

PyCheck helps you keep your codebase secure by automatically detecting and fixing hardcoded secrets before they reach production. Perfect for Django, Flask, and any Python project with configuration files.

---

## ✨ Features

### 🔍 Smart Detection
- **Comprehensive Pattern Matching**: Detects API keys, secret keys, passwords, tokens, and database credentials
- **Configuration-Focused**: Scans only relevant files (settings.py, config.py, .env, .yml, .yaml)
- **Context-Aware**: Skips already-commented lines and safely-configured environment variables
- **Multi-Format Support**: Python, YAML, ENV files

### 🛠️ Intelligent Auto-Fix
- **Three Fix Methods**:
  1. **Comment Out** - Temporary fix for quick security
  2. **Replace with `os.environ`** - Production-ready environment variable usage
  3. **Remove Lines** - Clean removal with warnings
- **Preview Before Fix**: See suggested changes before applying
- **Preserve Formatting**: Maintains indentation and code structure

### 🎯 Developer-Friendly
- **Interactive Mode**: Choose how to fix each issue
- **Silent Mode**: Perfect for CI/CD pipelines (`--no-prompt`)
- **Verbose Output**: Detailed scanning information when needed
- **Color-Coded Output**: Clear, readable terminal output

---

## 🚀 Quick Start

### Installation

```bash
# Install directly from GitHub
pip install git+https://github.com/Ranjith11903952/pycheck.git

# Verify installation
pycheck --help
```

### Basic Usage

```bash
# Scan current directory
pycheck .

# Scan specific directory
pycheck /path/to/your/project

# Scan specific file
pycheck settings.py

# Verbose mode (detailed output)
pycheck . --verbose

# Auto-fix mode (non-interactive)
pycheck . --auto-fix

# CI/CD mode (silent)
pycheck . --no-prompt
```

---

## 📋 What PyCheck Detects

| Category | Examples | Detection |
|----------|----------|-----------|
| **API Keys** | `API_KEY = "sk_live_abc123"` | ✅ |
| **Secret Keys** | `SECRET_KEY = "django-insecure-..."` | ✅ |
| **Passwords** | `DATABASE_PASSWORD = "mypass123"` | ✅ |
| **Database URLs** | `DATABASE_URL = "postgres://user:pass@host/db"` | ✅ |
| **Social Auth** | `SOCIAL_AUTH_GITHUB_SECRET = "..."` | ✅ |
| **Cloud Secrets** | `AWS_SECRET_ACCESS_KEY = "..."` | ✅ |
| **Tokens** | `AUTH_TOKEN = "ghp_abc123..."` | ✅ |
| **URLs with Credentials** | `API_URL = "https://user:pass@api.com"` | ✅ |

### ✅ What PyCheck Ignores

- Lines already using `os.environ.get()` or `os.getenv()`
- Commented-out lines
- Empty lines
- Files listed in `.pycheckignore`

---

## 🎮 Interactive Mode

When PyCheck detects issues, you'll see:

```
🚨 FOUND 3 SECURITY ISSUES
==========================================

📄 settings.py
  Line 25: SECRET_KEY = 'django-insecure-hardcoded-key'
  Line 42: DATABASE_PASSWORD = 'mypassword123'
  Line 58: API_KEY = 'sk_live_abc123xyz'

What would you like to do?
1. Show preview and choose fix method
2. Auto-fix with os.environ (recommended for production)
3. Show detailed suggestions

Enter choice (1-3): 
```

### Option 1: Preview and Choose

```
📝 PREVIEW OF CHANGES:

File: settings.py - Line 25
BEFORE: SECRET_KEY = 'django-insecure-hardcoded-key'
SUGGESTIONS:
  1. # SECRET_KEY = 'django-insecure-hardcoded-key'
  2. SECRET_KEY = os.environ.get('SECRET_KEY')

Choose fix method:
1. Comment out (temporary fix)
2. Replace with os.environ (production ready)
3. Remove lines

Enter fix method (1-3): 2

✅ Replaced 3 issues with os.environ in 1 files

Next steps:
  1. Set environment variables:
     export SECRET_KEY=your_value_here
     export DATABASE_PASSWORD=your_value_here
     export API_KEY=your_value_here
  2. Test your application with the new environment variables
```

### Option 2: Auto-Fix with os.environ

Instantly replaces all hardcoded secrets with `os.environ.get()` calls:

```python
# Before
SECRET_KEY = 'django-insecure-hardcoded-key-12345'
DATABASE_PASSWORD = 'mypassword123'
API_URL = 'https://api.example.com'

# After
SECRET_KEY = os.environ.get('SECRET_KEY')
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD')
API_URL = os.environ.get('API_URL', 'https://api.example.com')  # Default value shown
```

### Option 3: Detailed Suggestions

Get comprehensive advice for each issue:

```
💡 DETAILED SUGGESTIONS:

Issue #1
File: settings.py
Line 25: SECRET_KEY = 'django-insecure-hardcoded-key'

Recommended fixes:
  Option 1: # SECRET_KEY = 'django-insecure-hardcoded-key'
  Option 2: SECRET_KEY = os.environ.get('SECRET_KEY')

Best practice:
  • Use option 2 (os.environ) for production
  • Set the environment variable in your deployment
  • For Django: SECRET_KEY = os.environ.get('SECRET_KEY')
```

---

## 🔧 Command Reference

```bash
Usage: pycheck [PATH] [OPTIONS]

Arguments:
  PATH                       Directory or file to scan (default: current directory)

Options:
  -v, --verbose             Show detailed scanning progress
  --auto-fix                Automatically fix issues with os.environ
  --clean-commented         Remove already commented secrets
  --no-prompt               Skip all interactive prompts (CI/CD mode)
  --extensions EXT [EXT...]  File extensions to scan (default: .py .yml .yaml .env)
  --test                    Run the built-in test suite
  --test-comments           Test comment detection functionality
  --all-files               Scan all files (not just configuration files)
  --help                    Show this help message
```

---

## 📂 File Extensions

By default, PyCheck scans these file types:

- `.py` - Python files (settings.py, config.py)
- `.yml` / `.yaml` - YAML configuration files
- `.env` - Environment variable files

### Custom Extensions

```bash
# Scan specific file types
pycheck . --extensions .py .json .ini

# Scan only Python files
pycheck . --extensions .py
```

---

## 🙈 Ignoring Files and Patterns

Create a `.pycheckignore` file in your project root:

```
# Ignore specific variables
TEST_API_KEY
DUMMY_SECRET
SAMPLE_PASSWORD

# Ignore files
local_settings.py
test_config.py
*.sample.py

# Ignore directories
tests/
examples/
```

**Format Rules:**
- One pattern per line
- Lines starting with `#` are comments
- Empty lines are ignored
- Patterns are case-sensitive

---

## 💡 Use Cases

### 1. Pre-Commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
pycheck . --no-prompt
if [ $? -ne 0 ]; then
    echo "❌ Security issues found! Please fix before committing."
    exit 1
fi
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### 2. CI/CD Pipeline

**GitHub Actions** (`.github/workflows/security-scan.yml`):

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install PyCheck
        run: pip install git+https://github.com/Ranjith11903952/pycheck.git
      - name: Run Security Scan
        run: pycheck . --no-prompt
```

**GitLab CI** (`.gitlab-ci.yml`):

```yaml
security-scan:
  stage: test
  image: python:3.9
  script:
    - pip install git+https://github.com/Ranjith11903952/pycheck.git
    - pycheck . --no-prompt
  allow_failure: false
```

### 3. Docker Integration

```dockerfile
# Add to your Dockerfile
RUN pip install git+https://github.com/Ranjith11903952/pycheck.git

# Run scan during build
RUN pycheck /app --no-prompt || exit 1
```

### 4. Manual Security Audit

```bash
# Comprehensive scan with detailed output
pycheck . --verbose

# Generate report (redirect output)
pycheck . --verbose > security-report.txt
```

---

## 🎯 Best Practices

### ✅ Do's

1. **Run Early and Often**
   ```bash
   # Before committing
   pycheck .
   ```

2. **Use Environment Variables**
   ```python
   # ✅ Good
   SECRET_KEY = os.environ.get('SECRET_KEY')
   
   # ❌ Bad
   SECRET_KEY = 'hardcoded-secret-123'
   ```

3. **Set Defaults for Non-Sensitive Values**
   ```python
   API_URL = os.environ.get('API_URL', 'http://localhost:8000')
   DEBUG = os.environ.get('DEBUG', 'False') == 'True'
   ```

4. **Use `.env` Files for Local Development**
   ```bash
   # .env (never commit this!)
   SECRET_KEY=dev-secret-key-123
   DATABASE_URL=postgres://localhost/mydb
   ```

5. **Add PyCheck to CI/CD**
   ```bash
   pycheck . --no-prompt
   ```

### ❌ Don'ts

1. **Don't commit hardcoded secrets**
   ```python
   # ❌ Never do this
   PASSWORD = 'admin123'
   API_KEY = 'sk_live_abc123'
   ```

2. **Don't disable PyCheck for entire projects**
   - Use `.pycheckignore` for specific cases only

3. **Don't store secrets in version control**
   - Use environment variables
   - Use secret management services (AWS Secrets Manager, HashiCorp Vault)

4. **Don't ignore PyCheck warnings without investigation**
   - Every detection is a potential security risk

---

## 🔒 Security Patterns Detected

### Pattern Categories

#### 1. API Keys and Tokens
```python
API_KEY = "sk_live_abc123"
STRIPE_API_KEY = "sk_test_xyz789"
GITHUB_TOKEN = "ghp_abc123xyz"
```

#### 2. Secret Keys
```python
SECRET_KEY = "django-insecure-key"
JWT_SECRET = "my-jwt-secret"
ENCRYPTION_KEY = "aes-key-123"
```

#### 3. Database Credentials
```python
DATABASE_PASSWORD = "dbpass123"
DATABASE_URL = "postgres://user:pass@localhost/db"
DB_HOST = "db.example.com"
```

#### 4. Social Authentication
```python
SOCIAL_AUTH_GOOGLE_SECRET = "google-secret"
SOCIAL_AUTH_GITHUB_KEY = "github-key"
FACEBOOK_APP_SECRET = "fb-secret"
```

#### 5. Cloud Provider Secrets
```python
AWS_SECRET_ACCESS_KEY = "aws-secret"
AZURE_CLIENT_SECRET = "azure-secret"
GCP_SERVICE_KEY = "gcp-key"
```

---

## 🧪 Testing

PyCheck includes built-in tests to verify functionality:

```bash
# Run test suite
pycheck --test

# Test comment detection
pycheck --test-comments
```

### Test Output Example

```
🧪 TESTING SCANNER SUGGESTIONS
==========================================

Test: SECRET_KEY = 'django-insecure-hardcoded-key-12345'
Detected as secret
Suggestions:
  1. # SECRET_KEY = 'django-insecure-hardcoded-key-12345'
  2. SECRET_KEY = os.environ.get('SECRET_KEY')

Test: DEBUG = True
✅ Safe line
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. "Command not found: pycheck"

**Solution:**
```bash
# Check if Python scripts directory is in PATH
python -m pip show pycheck

# Or run directly
python -m pycheck .
```

#### 2. "No configuration files found"

**Cause:** PyCheck only scans files with specific names (settings, config, etc.)

**Solution:**
```bash
# Scan all files with specific extensions
pycheck . --extensions .py --all-files

# Or scan specific file
pycheck myfile.py
```

#### 3. "Too many false positives"

**Solution:**
Use `.pycheckignore` to exclude specific patterns:
```
# .pycheckignore
TEST_SECRET
EXAMPLE_KEY
SAMPLE_*
```

#### 4. "Installation fails"

**Solution:**
```bash
# Ensure Git is installed
git --version

# Install with verbose output
pip install -v git+https://github.com/Ranjith11903952/pycheck.git

# Or clone and install locally
git clone https://github.com/Ranjith11903952/pycheck.git
cd pycheck
pip install -e .
```

---

## 🔄 Exit Codes

PyCheck uses standard exit codes for CI/CD integration:

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | Success | No security issues found |
| `1` | Failure | Security issues detected |
| `130` | Interrupted | User cancelled (Ctrl+C) |

### CI/CD Usage

```bash
pycheck . --no-prompt
if [ $? -eq 0 ]; then
    echo "✅ Security scan passed"
else
    echo "❌ Security issues found"
    exit 1
fi
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

1. Check [existing issues](https://github.com/Ranjith11903952/pycheck/issues)
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - PyCheck version (`pip show pycheck`)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Ranjith11903952/pycheck.git
cd pycheck

# Install in development mode
pip install -e .

# Make changes and test
pycheck --test
```

### Code Style

- Follow PEP 8 guidelines
- Add docstrings to functions
- Include type hints
- Test your changes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by security best practices from the OWASP community
- Built with ❤️ for Python developers
- Special thanks to all contributors

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Ranjith11903952/pycheck/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Ranjith11903952/pycheck/discussions)

---

## 🌟 Show Your Support

If PyCheck helped secure your project, please consider:

- ⭐ **Starring** the repository
- 🐛 **Reporting bugs** you encounter
- 💡 **Suggesting features** you'd like to see
- 🔀 **Contributing** code improvements

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/Ranjith11903952/pycheck?style=social)
![GitHub forks](https://img.shields.io/github/forks/Ranjith11903952/pycheck?style=social)
![GitHub issues](https://img.shields.io/github/issues/Ranjith11903952/pycheck)
![GitHub last commit](https://img.shields.io/github/last-commit/Ranjith11903952/pycheck)

---

<div align="center">

**Made with ❤️ by [Ranjith](https://github.com/Ranjith11903952)**

*Keep your secrets safe, keep your code secure* 🔐

[Report Bug](https://github.com/Ranjith11903952/pycheck/issues) · [Request Feature](https://github.com/Ranjith11903952/pycheck/issues) · [Documentation](https://github.com/Ranjith11903952/pycheck/wiki)

</div>
