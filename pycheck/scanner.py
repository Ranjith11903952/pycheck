import os
import re
from typing import List, Dict, Any, Optional
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def load_ignore_patterns(directory: str) -> List[str]:
    """Load patterns to ignore from .pycheckignore file"""
    ignore_file = os.path.join(directory, '.pycheckignore')
    if os.path.exists(ignore_file):
        with open(ignore_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

def should_skip_line(line: str, ignore_patterns: List[str]) -> bool:
    """Check if line should be skipped from secret detection"""
    trimmed = line.strip()
    
    # Skip empty lines
    if not trimmed:
        return True
        
    # Skip fully commented lines
    if trimmed.startswith(('#', '//', '/*', '*/', '<!--', '-->')):
        return True
        
    # Skip common documentation patterns
    if any(trimmed.startswith(p) for p in ('@', '::', '..', '*', '"""', "'''")):
        return True
        
    # Skip whitelisted patterns
    if any(re.search(pattern, trimmed, re.IGNORECASE) for pattern in ignore_patterns):
        return True
        
    return False

def scan_directory(
    directory: str,
    verbose: bool = False,
    auto_fix: bool = False,
    clean_commented: bool = False,
    extensions: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Scans directory for sensitive data with improved detection
    
    Args:
        directory: Path to directory to scan
        verbose: Show detailed progress
        auto_fix: Automatically comment found issues
        clean_commented: Remove commented-out secrets
        extensions: Only scan files with these extensions
        
    Returns:
        List of found issues with file, line, and content
    """
    issues = []
    modified_files = set()
    ignore_patterns = load_ignore_patterns(directory)
    
    # Secret patterns to detect
    active_patterns = [
        r'(?<![\#\/])\bAPI_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'(?<![\#\/])\bSECRET_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'(?<![\#\/])\bACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'(?<![\#\/])\bTOKEN\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'(?<![\#\/])\bPASSWORD\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'(?<![\#\/])\bCREDENTIALS\s*[:=]\s*["\']?[^"\'\s]+["\']?',
    ]
    
    commented_patterns = [
    # Hardcoded sensitive dictionary entries (e.g., "HOST": "value")
    r'["\']\b(DB_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|DATABASE_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|HOST|PORT)\b["\']\s*:\s*["\'](?!os\.environ|os\.getenv)[^"\']+["\']',

    # Regular key=value assignments (non-dict)
    r'\b(DB_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|DATABASE_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|HOST|PORT)\s*[:=]\s*["\'](?!os\.environ|os\.getenv)[^"\']+["\']',

    # Optional: commented hardcoded secrets
    r'[\#\/].*\b(DB_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|DATABASE_?(HOST|NAME|USER|USERNAME|PASSWORD|PORT|URI|URL)|HOST|PORT)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
    ]

    
    patterns = commented_patterns if clean_commented else active_patterns

    # Config files to scan
    config_files = [
        r'settings\.py$', r'config\.py$', r'secrets\.py$',
        r'\.env$', r'config\.js$', r'application\.properties$',
        r'application\.yml$', r'config\.php$', r'\.env\..*$',
        r'config\.json$'
    ]
    
    if extensions:
        config_files = [fr'\.{ext}$' for ext in extensions]

    # Collect all files to scan
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

            lines = content.splitlines()
            modified = False
            
            for line_num, line in enumerate(lines, 1):
                if should_skip_line(line, ignore_patterns):
                    continue
                    
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'content': line.strip(),
                            'pattern': pattern,
                            'commented': line.strip().startswith(('#', '//'))
                        })
                        
                        if auto_fix or clean_commented:
                            ext = os.path.splitext(file_path)[1].lower()
                            if ext in ('.py', '.sh', '.php', '.js', '.rb'):
                                prefix = '# '
                            elif ext in ('.java', '.c', '.cpp', '.h', '.cs'):
                                prefix = '// '
                            elif ext in ('.html', '.xml'):
                                prefix = '<!-- '
                                suffix = ' -->'
                            else:
                                prefix = '# '
                            
                            if clean_commented:
                                lines[line_num-1] = ''
                            else:
                                if ext in ('.html', '.xml'):
                                    lines[line_num-1] = f"{prefix}{lines[line_num-1].rstrip()}{suffix}\n"
                                else:
                                    lines[line_num-1] = f"{prefix}{lines[line_num-1]}"
                            
                            modified = True
                        break

            if modified:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(lines))
                    modified_files.add(file_path)
                except Exception as e:
                    if verbose:
                        print(f"{Fore.RED}Failed to modify {file_path}: {e}{Style.RESET_ALL}")

        except Exception as e:
            if verbose:
                print(f"{Fore.YELLOW}⚠️ Could not scan {file_path}: {e}{Style.RESET_ALL}")

    # Display results
    print("\n" + "="*50 + "\n")

    if issues:
        print(f"{Fore.RED}❌ SECURITY ISSUES FOUND ({len(issues)}){Style.RESET_ALL}\n")
        for issue in issues:
            status = "Commented" if issue['commented'] else "Active"
            color = Fore.YELLOW if issue['commented'] else Fore.RED
            print(f"{color}[{status}]{Style.RESET_ALL} {Fore.YELLOW}File:{Style.RESET_ALL} {issue['file']}")
            print(f"{Fore.CYAN}Line {issue['line']}:{Style.RESET_ALL} {issue['content']}")
            print(f"{Fore.MAGENTA}Pattern:{Style.RESET_ALL} {issue['pattern']}")
            print("-" * 50)
        
        if not auto_fix and not clean_commented and any(not issue['commented'] for issue in issues):
            user_input = input(f"\n{Fore.YELLOW}Do you want to comment out active secrets? (Yes/No): {Style.RESET_ALL}").strip().lower()
            if user_input in ('y', 'yes'):
                return scan_directory(directory, verbose, True, False, extensions)
    else:
        print(f"{Fore.GREEN}✅ No security issues found{Style.RESET_ALL}")

    if modified_files:
        print(f"\n{Fore.GREEN}✅ Modified {len(modified_files)} files:{Style.RESET_ALL}")
        for modified_file in modified_files:
            print(f" - {modified_file}")

    return issues
