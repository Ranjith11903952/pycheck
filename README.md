Here's the updated `README.md` with your specific GitHub repository and usage example:

```markdown
# PyCheck - Sensitive Data Scanner 🔍

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A security tool to scan projects for exposed secrets and sensitive data with automatic remediation.

## Installation ⚙️

Install directly from GitHub:

```bash
pip install git+https://github.com/Ranjith11903952/pycheck.git
```

## Basic Usage 🚀

Scan a directory:

```bash
pycheck testdata/
```

This will:
1. Recursively scan all files in `testdata/` directory
2. Show detected secrets with file locations
3. Prompt to automatically comment them out

## Full Command Reference 📖

```
Usage: pycheck [PATH] [OPTIONS]

Options:
  PATH            Directory to scan (default: current directory)
  --verbose       Show detailed scanning progress
  --auto-fix      Automatically comment findings without confirmation
  --extensions    Limit to specific file extensions (comma-separated)
  --version       Show version
  --help          Show help message
```

## Examples 💡

Scan current directory with verbose output:
```bash
pycheck . --verbose
```

Scan only Python and .env files:
```bash
pycheck testdata/ --extensions .py,.env
```

Auto-fix without confirmation (careful!):
```bash
pycheck testdata/ --auto-fix
```

## What It Finds 🔎

Detects:
- API keys (`API_KEY`, `apiKey`)
- Secret keys (`SECRET_KEY`)
- Access credentials
- Tokens
- Passwords
- And other sensitive patterns

## Sample Output 📋

```
$ pycheck testdata/
Scanning files: 100%|██████████| 42/42 [00:01<00:00, 35.2 files/s]

❌ SECURITY ISSUES FOUND (2)

File: testdata/config.py
Line 15: AWS_ACCESS_KEY = 'AKIA1234567890'
Pattern: ACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?

--------------------------------------------------

Do you want to comment out these sensitive lines? [y/N]: y
✅ Fixed 1 files
```

## Development 🛠️

1. Clone repository:
```bash
git clone https://github.com/Ranjith11903952/pycheck.git
cd pycheck
pip install -e .
```

2. Run tests:
```bash
pytest
```

## License 📄
MIT - See [LICENSE](LICENSE) for details.
```

Key changes made:
1. Updated all installation instructions to use your GitHub repo URL
2. Made `pycheck testdata/` the primary example
3. Simplified the command reference to match your actual CLI
4. Added clear examples of different scanning modes
5. Included the actual expected output format
6. Kept the development setup simple and clear

The README now accurately reflects:
- Your package name (`pycheck`)
- Your GitHub repository
- The actual command syntax
- Realistic usage examples
- Expected output format

You may want to add:
- A `pyproject.toml` or `setup.py` if not already present
- Actual screenshots of the tool in action
- More detailed documentation about the detection patterns
- CI/CD badges if you have tests set up
