import os
import re
import sys
from typing import List, Dict, Any
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def scan_directory(directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Scans directory for sensitive data with colored output and progress tracking
    
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
        # Python
        r'settings\.py$', r'config\.py$', r'secrets\.py$',
        # JavaScript/Node
        r'\.env$', r'config\.js$',
        # Java
        r'application\.properties$', r'application\.yml$',
        # PHP
        r'config\.php$',
        # General
        r'\.env\..*$', r'config\.json$'
    ]

    # Get all files first for accurate progress
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
                        # Print immediately when found
                        print(f"\n{Fore.RED}⚠️ SECURITY ISSUE FOUND{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}File:{Style.RESET_ALL} {file_path}")
                        print(f"{Fore.YELLOW}Line {line_num}:{Style.RESET_ALL} {line.strip()}")
                        print(f"{Fore.CYAN}Pattern:{Style.RESET_ALL} {pattern}")
                        break

        except Exception as e:
            if verbose:
                print(f"{Fore.YELLOW}⚠️ Could not scan {file_path}: {e}{Style.RESET_ALL}")

    # Final summary
    if issues:
        print(f"\n{Fore.RED}❌ Found {len(issues)} security issues!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}✅ No security issues found{Style.RESET_ALL}")

    return issues
