````markdown
# PyCheck - Security Scanner for Configuration Files 🔐

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

**PyCheck** is a security tool that scans configuration files for hardcoded secrets and sensitive data — with smart auto-fix options and environment-variable-based patches.

Stay secure and ship clean code effortlessly. 🚀

---

## Installation ⚙️

### Quick Install from GitHub
```bash
pip install git+https://github.com/Ranjith11903952/pycheck.git
````

That’s it! PyCheck is now installed globally.

Verify installation:

```bash
pycheck --help
```

---

## Quick Start 🚀

Scan your current directory:

```bash
pycheck .
```

**Example output:**

```
🔍 pycheck - Security Scanner
Scanning: .

📁 Found 3 configuration files...
🔍 Scanning 3 configuration files...

📊 SCAN RESULTS
==========================================

🚨 FOUND 2 SECURITY ISSUES
==========================================

📄 settings.py
  Line 25: SECRET_KEY = 'django-insecure-hardcoded'
  Line 42: DATABASE_PASSWORD = 'mypassword123'

What would you like to do?
1. Show preview and choose fix method
2. Auto-fix with os.environ (recommended for production)
3. Show detailed suggestions
```

---

## Features ✨

### 🔍 Smart Detection

PyCheck scans only configuration-related files such as:

* `settings.py`
* `config.py`
* `.env`
* `.yaml`, `.yml`
* `.ini`, `.json`

It detects:

* API keys
* Secrets
* Database credentials
* Tokens & authentication strings
* URLs containing sensitive data
* Social auth keys
* Cloud provider secrets (AWS/GCP/Azure)

---

### 🔧 Smart Fixing

**Three secure fix options:**

1. **Preview changes** before applying
2. **Auto-fix** using `os.environ.get()` (Best for production)
3. **Detailed suggestions** for manual fixes

---

### 💡 Smart Suggestions Include:

* Commenting out insecure lines
* Replacing with environment variables
* Removal guidelines with instructions

---

## Usage Examples 💡

### Basic Scan

```bash
pycheck .
pycheck /path/to/project/
pycheck settings.py
```

### Verbose Mode

```bash
pycheck . --verbose
```

### Auto-Fix Mode

```bash
pycheck . --auto-fix
```

### Skip Prompts (CI/CD friendly)

```bash
pycheck . --no-prompt
```

---

## Command Reference 📖

```bash
Usage: pycheck [PATH] [OPTIONS]

Arguments:
  PATH                    Directory or file to scan (default: current directory)

Options:
  -v, --verbose           Show detailed scanning progress
  --auto-fix              Automatically fix issues with os.environ
  --no-prompt             Skip all interactive prompts
  --extensions EXTENSIONS Specify file extensions to scan
  --test                  Run the built-in test suite
  --help                  Show help message
```

---

## Advanced Usage 🛠️

### Custom File Extensions

```bash
pycheck . --extensions .py .yml .yaml .env
```

### Test the Scanner

```bash
pycheck --test
```

---

## What PyCheck Detects 🔎

| Pattern         | Example                             | Detection |
| --------------- | ----------------------------------- | --------- |
| API Keys        | `API_KEY = "sk_live_123"`           | ✅         |
| Secrets         | `SECRET_KEY = "django-insecure"`    | ✅         |
| Passwords       | `DATABASE_PASSWORD = "pass123"`     | ✅         |
| URLs with creds | `postgres://user:pass@host`         | ✅         |
| Social auth     | `SOCIAL_AUTH_GITHUB_SECRET = "..."` | ✅         |
| Cloud secrets   | `AWS_SECRET_KEY = "..."`            | ✅         |

---

## Integration 🔄

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Ranjith11903952/pycheck
    rev: main
    hooks:
      - id: pycheck
        args: [--no-prompt]
```

### GitHub Actions (CI/CD)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run PyCheck
        run: |
          pip install git+https://github.com/Ranjith11903952/pycheck.git
          pycheck . --no-prompt
```

---

## Configuration ⚙️

### `.pycheckignore`

Ignore patterns or files:

```bash
# Ignore test credentials
TEST_API_KEY
DUMMY_SECRET

# Ignore specific files
local_settings.py
```

---

## Development Setup (For Contributors) 🛠️

```bash
git clone https://github.com/Ranjith11903952/pycheck.git
cd pycheck
pip install -e .
```

---

## Best Practices 📋

* Run PyCheck early and often during development
* Use `--auto-fix` for production-ready code
* Add PyCheck to your pre-commit workflow
* Integrate into CI/CD to prevent secret leaks

---

## Common Issues & Solutions 🔧

| Issue                         | Solution                                              |
| ----------------------------- | ----------------------------------------------------- |
| Installation fails            | Install Git (`apt install git`)                       |
| "Command not found"           | Add Python scripts to PATH or use `python -m pycheck` |
| Too many false positives      | Use `.pycheckignore`                                  |
| Need to keep specific secrets | Add patterns to `.pycheckignore`                      |

---

## License 📄

Licensed under the **MIT License**.
See the `LICENSE` file for details.

---

## Support ❤️

Found a bug? Want a feature?
👉 Open an **Issue** on GitHub!

If you like the project, ⭐ **Star the repository**!

Made with ❤️ by **Ranjith**
Stay secure, stay awesome! 🔐✨

```

---

If you want, I can also:

✅ Add a project logo  
✅ Add a PyPI version badge (when you publish it)  
✅ Add GIF or screenshot of usage  
✅ Improve formatting or styling  

Just tell me!
```
