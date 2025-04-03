import os
import re
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_directory(directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Scans a directory for files containing sensitive data patterns.
    
    Args:
        directory (str): The directory to scan
        verbose (bool): Whether to show verbose output
        
    Returns:
        List[Dict[str, Any]]: Found security issues
    """
    issues = []
    
    # Patterns to detect secrets
    sensitive_patterns = [
        r'API_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'SECRET_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'ACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'TOKEN\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PASSWORD\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'CREDENTIALS\s*[:=]\s*["\']?[^"\'\s]+["\']?',
    ]

    # Configuration files to check (multi-language support)
    config_files = [
        # Python
        r'settings\.py$',
        r'config\.py$',
        r'secrets\.py$',
        
        # JavaScript/Node
        r'\.env$',
        r'config\.js$',
        
        # Java
        r'application\.properties$',
        r'application\.yml$',
        
        # PHP
        r'config\.php$',
        
        # General
        r'\.env\..*$',
        r'config\.json$',
    ]

    # Walk through directory
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip non-config files
            if not any(re.search(pattern, file) for pattern in config_files):
                if verbose:
                    logging.info(f"Skipping non-config file: {file_path}")
                continue
            
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
                                'line_content': line.strip(),
                                'pattern': pattern
                            })
                            break  # Only report first match per line
                            
            except Exception as e:
                logging.error(f"Error scanning {file_path}: {str(e)}")
    
    return issues
