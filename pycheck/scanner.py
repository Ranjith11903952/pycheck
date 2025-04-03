import os
import re
from typing import List, Dict, Any
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def scan_directory(directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Scans directory for sensitive data with improved output formatting
    
    Args:
        directory: Path to directory to scan
        verbose: Show detailed progress
    
    Returns:
        List of found issues with file, line, and content
    """
    issues = []
    
    # Secret patterns to detect
    sensitive_patterns = [
        r'API_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'SECRET_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'ACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'TOKEN\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PASSWORD\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'CREDENTIALS\s*[:=]\s*["\']?[^"\'\s]+["\']?',
    ]

    # Config files to scan (multi-language support)
    config_files = [
        r'settings\.py$', r'config\.py$', r'secrets\.py$',
        r'\.env$', r'config\.js$', r'application\.properties$',
        r'application\.yml$', r'config\.php$', r'\.env\..*$',
        r'config\.json$'
    ]

    # First collect all files to scan
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(re.search(p, file) for p in config_files):
                all_files.append(os.path.join(root, file))

    # Scan files with progress bar
    for file_path in tqdm(all_files, desc="Scanning files", unit="file"):
        try:
            # Try UTF-8 first, then fallback
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(file_path, 'rb') as f:
                    content = f.read().decode('latin-1')

            # Check each line
            for line_num, line in enumerate(content.splitlines(), 1):
                for pattern in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'content': line.strip(),
                            'pattern': pattern
                        })
                        break  # Only report first match per line

        except Exception as e:
            if verbose:
                print(f"{Fore.YELLOW}⚠️ Could not scan {file_path}: {e}{Style.RESET_ALL}")

    # Clear progress bar
    print("\n" + "="*50 + "\n")

    # Display all issues after scanning completes
    if issues:
        print(f"{Fore.RED}❌ SECURITY ISSUES FOUND ({len(issues)}){Style.RESET_ALL}\n")
        for issue in issues:
            print(f"{Fore.YELLOW}File:{Style.RESET_ALL} {issue['file']}")
            print(f"{Fore.CYAN}Line {issue['line']}:{Style.RESET_ALL} {issue['content']}")
            print(f"{Fore.MAGENTA}Pattern:{Style.RESET_ALL} {issue['pattern']}")
            print("-" * 50)
    else:
        print(f"{Fore.GREEN}✅ No security issues found{Style.RESET_ALL}")

    return issues
