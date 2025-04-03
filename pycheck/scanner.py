import os
import re
import sys
import logging
from typing import List, Dict, Any, Optional
from tqdm import tqdm
from colorama import Fore, Style, init
import shutil

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecretScanner:
    """Enhanced secret scanner with multi-language support and remediation"""
    
    def __init__(self):
        # Define sensitive patterns
        self.sensitive_patterns = [
            # API/access keys
            r'(?:api|secret|access|auth|private|encryption)[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'token\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            
            # Credentials
            r'(?:password|passwd|pwd|credential)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'(?:user(?:name)?|login)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            
            # Database configurations
            r'db(?:_(?:name|user|pass(word)?|host|port))\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'(?:database|connection)[_-]?(?:url|string)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            
            # Cloud/AWS
            r'aws[_-](?:access[_-]?key|secret[_-]?key|session[_-]?token)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            
            # SSH/Keys
            r'ssh[_-]?(?:key|passphrase)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'(?:private|public)[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        ]

        # Language-specific configuration file patterns
        self.config_file_patterns = {
            'python': [
                r'settings\.py$',
                r'config\.py$',
                r'secrets\.py$',
                r'local_settings\.py$',
                r'[^/]+/settings/.*\.py$'  # Django settings modules
            ],
            'javascript': [
                r'config\.js$',
                r'\.env(\..+)?$',
                r'secrets\.js$'
            ],
            'java': [
                r'application\.(properties|yml|yaml)$',
                r'bootstrap\.(properties|yml|yaml)$'
            ],
            'dotnet': [
                r'appsettings\.json$',
                r'web\.config$',
                r'app\.config$'
            ],
            'php': [
                r'config\.php$',
                r'\.env(\..+)?$',
                r'database\.php$'
            ],
            'ruby': [
                r'application\.rb$',
                r'secrets\.yml$',
                r'credentials\.yml\.enc$'
            ],
            'general': [
                r'config\.(json|yaml|yml|toml|xml|ini)$',
                r'credentials?\.(json|yaml|yml)$',
                r'secrets?\.(json|yaml|yml)$',
                r'\.(npmrc|htpasswd|git-credentials)$'
            ]
        }

    def is_config_file(self, filename: str) -> bool:
        """Check if file matches any known configuration file pattern"""
        filename_lower = filename.lower()
        return any(
            re.search(pattern, filename_lower, re.IGNORECASE)
            for patterns in self.config_file_patterns.values()
            for pattern in patterns
        )

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for sensitive patterns"""
        issues = []
        
        try:
            # Try reading with UTF-8 first, fallback to latin-1
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(file_path, 'rb') as f:
                    content = f.read().decode('latin-1')
            
            for line_num, line in enumerate(content.splitlines(), 1):
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'line_content': line.strip(),
                            'pattern': pattern,
                            'severity': 'high'
                        })
                        break  # Only report first match per line
        
        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")
        
        return issues

    def display_issue(self, issue: Dict[str, Any]):
        """Display an issue with colored output"""
        print(f"\n{Fore.RED}SECURITY ISSUE FOUND{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}File:{Style.RESET_ALL} {issue['file']}")
        print(f"{Fore.YELLOW}Line {issue['line']}:{Style.RESET_ALL} {issue['line_content']}")
        print(f"{Fore.YELLOW}Pattern:{Style.RESET_ALL} {issue['pattern']}")

    def suggest_fix(self, issue: Dict[str, Any]) -> str:
        """Generate suggested fix for an issue"""
        line = issue['line_content']
        if ':=' in line:
            key, _ = line.split(':=', 1)
            return f"{key.strip()} := os.getenv('{key.strip().upper()}')"
        elif '=' in line:
            key, _ = line.split('=', 1)
            return f"{key.strip()} = os.getenv('{key.strip().upper()}')"
        elif ':' in line:
            key, _ = line.split(':', 1)
            return f"{key.strip()}: os.getenv('{key.strip().upper()}')"
        return line

    def prompt_remediation(self, issue: Dict[str, Any]) -> bool:
        """Prompt user for remediation action"""
        self.display_issue(issue)
        print(f"\n{Fore.GREEN}Suggested fix:{Style.RESET_ALL} {self.suggest_fix(issue)}")
        
        while True:
            choice = input(f"\n{Fore.CYAN}Choose action: [s]kip, [r]eplace, [a]bort: {Style.RESET_ALL}").lower()
            if choice in ('s', 'skip'):
                return False
            elif choice in ('r', 'replace'):
                return True
            elif choice in ('a', 'abort'):
                sys.exit(0)
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def apply_fix(self, file_path: str, issue: Dict[str, Any]) -> bool:
        """Apply the suggested fix to the file"""
        backup_path = f"{file_path}.bak"
        
        try:
            # Create backup
            shutil.copy2(file_path, backup_path)
            
            # Read original content
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            # Apply fix
            lines[issue['line']-1] = self.suggest_fix(issue) + '\n'
            
            # Write modified content
            with open(file_path, 'w') as f:
                f.writelines(lines)
            
            print(f"{Fore.GREEN}Fixed applied. Backup saved to {backup_path}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error applying fix: {str(e)}{Style.RESET_ALL}")
            return False

    def scan_directory(self, directory: str, interactive: bool = True) -> Dict[str, Any]:
        """Scan directory and optionally remediate issues"""
        results = {
            'scanned_files': 0,
            'secrets_found': 0,
            'files_modified': 0,
            'issues': []
        }
        
        # Get all config files
        config_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if self.is_config_file(file):
                    config_files.append(os.path.join(root, file))
        
        # Scan files with progress bar
        print(f"\n{Fore.BLUE}Scanning {len(config_files)} configuration files...{Style.RESET_ALL}")
        for file_path in tqdm(config_files, desc="Scanning", unit="file"):
            results['scanned_files'] += 1
            issues = self.scan_file(file_path)
            
            if issues:
                results['secrets_found'] += len(issues)
                results['issues'].extend(issues)
                
                if interactive:
                    for issue in issues:
                        if self.prompt_remediation(issue):
                            if self.apply_fix(issue['file'], issue):
                                results['files_modified'] += 1
        
        # Print summary
        print(f"\n{Fore.BLUE}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Files scanned: {results['scanned_files']}")
        print(f"Secrets found: {results['secrets_found']}")
        print(f"Files modified: {results['files_modified']}")
        
        return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan for secrets in configuration files")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--auto", action="store_true", help="Run without prompts")
    args = parser.parse_args()
    
    scanner = SecretScanner()
    results = scanner.scan_directory(args.directory, interactive=not args.auto)
    
    if results['secrets_found'] > 0:
        sys.exit(1)  # Exit with error code if issues found


if __name__ == "__main__":
    main()
