import os
import re
import logging
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecretScanner:
    """Scanner for sensitive data in configuration files across multiple languages"""
    
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
            
            # Payment processors
            r'(?:stripe|paypal)[_-](?:api|secret)[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            
            # Social media
            r'(?:facebook|twitter|google|github)[_-](?:api|secret)[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
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
            'ruby': [
                r'application\.rb$',
                r'secrets\.yml$',
                r'credentials\.yml\.enc$'
            ],
            'php': [
                r'config\.php$',
                r'\.env(\..+)?$',
                r'database\.php$'
            ],
            'dotenv': [
                r'\.env(\..+)?$'
            ],
            'general': [
                r'config\.(json|yaml|yml|toml|xml|ini)$',
                r'credentials?\.(json|yaml|yml)$',
                r'secrets?\.(json|yaml|yml)$',
                r'\.(npmrc|htpasswd|git-credentials)$'
            ]
        }
        
        # Patterns to exclude (comments, docstrings, etc.)
        self.exclude_patterns = [
            r'^\s*[#/]',  # Comments
            r'^\s*/\*', r'\*/',  # Block comments
            r'^\s*[\'"]{3}',  # Docstrings
            r'@[\w\d_]+',  # Annotations
            r'\b(?:TODO|FIXME|XXX|HACK)\b',  # Code tags
            r'example|sample|placeholder',  # Example values
            r'ace\.define|regex:"',  # Specific false positives
        ]
        
        # File extensions to consider
        self.valid_extensions = (
            '.py', '.js', '.java', '.rb', '.php', 
            '.env', '.json', '.yaml', '.yml', '.ini', 
            '.properties', '.toml', '.xml', '.cfg'
        )

    def is_config_file(self, filename: str) -> bool:
        """Check if file matches any known configuration file pattern"""
        filename_lower = filename.lower()
        return any(
            re.search(pattern, filename_lower, re.IGNORECASE)
            for patterns in self.config_file_patterns.values()
            for pattern in patterns
        )

    def is_comment_or_excluded(self, line: str) -> bool:
        """Check if line should be excluded from scanning"""
        return any(re.search(pattern, line) for pattern in self.exclude_patterns)

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
            
            in_comment_block = False
            for line_num, line in enumerate(content.splitlines(), 1):
                # Handle comment blocks
                if re.search(r'^\s*/\*', line):
                    in_comment_block = True
                if in_comment_block:
                    if re.search(r'\*/', line):
                        in_comment_block = False
                    continue
                if re.search(r'^\s*[\'"]{3}', line):
                    in_comment_block = not in_comment_block
                    continue
                
                # Skip excluded lines
                if in_comment_block or self.is_comment_or_excluded(line):
                    continue
                
                # Check for sensitive patterns
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

    def scan_directory(self, directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan a directory for sensitive data in configuration files"""
        if not os.path.isdir(directory):
            raise ValueError(f"Directory not found: {directory}")
        
        issues = []
        total_files = 0
        scanned_files = 0
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                total_files += 1
                
                # Skip non-config files
                if (not file.lower().endswith(self.valid_extensions) and (not self.is_config_file(file)):
                    if verbose:
                        logging.debug(f"Skipping non-config file: {file_path}")
                    continue
                
                scanned_files += 1
                file_issues = self.scan_file(file_path)
                if file_issues:
                    issues.extend(file_issues)
                    logging.warning(f"Found {len(file_issues)} issues in {file_path}")
        
        logging.info(f"Scanned {scanned_files}/{total_files} files, found {len(issues)} potential secrets")
        return issues


def save_results(results: List[Dict[str, Any]], output_file: str = "secret_scan_results.json"):
    """Save scan results to JSON file"""
    import json
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save results: {str(e)}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan for secrets in configuration files")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file path", default="secret_scan_results.json")
    
    args = parser.parse_args()
    
    scanner = SecretScanner()
    results = scanner.scan_directory(args.directory, args.verbose)
    
    if results:
        save_results(results, args.output)
        logging.warning(f"Found {len(results)} potential secrets!")
    else:
        logging.info("No secrets found in configuration files")
