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
        directory (str): The directory to scan.
        verbose (bool): If True, print detailed logs for skipped files.

    Returns:
        List[Dict[str, Any]]: A list of issues found.
    """
    issues = []

    sensitive_patterns = [
        r'API_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'SECRET_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'ACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'TOKEN\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PASSWORD\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'CREDENTIALS\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'AUTH_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PRIVATE_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'USERNAME\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'USER_?NAME\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'DB_?NAME\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'DB_?PASSWORD\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'DB_?HOST\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'DATABASE_?URL\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'CONNECTION_?STRING\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'AWS_?ACCESS_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'AWS_?SECRET_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'SSH_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PRIVATE_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'PUBLIC_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',
        r'ENCRYPTION_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?'
    ]

    secret_file_patterns = [
        r'settings\.py$',
        r'config\.py$',
        r'secrets\.py$',
        r'local_settings\.py$',
        r'\.env$',
        r'\.env\.local$',
        r'\.env\.dev$',
        r'\.env\.prod$',
        r'\.env\.example$',
        r'config\.json$',
        r'config\.yaml$',
        r'config\.yml$',
        r'configuration\.json$',
        r'appsettings\.json$',
        r'\.properties$',
        r'credentials\.json$',
        r'secrets\.json$',
        r'keys\.json$',
        r'\.npmrc$',
        r'\.htpasswd$',
        r'\.git-credentials$'
    ]

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            if not any(re.search(pattern, file) for pattern in secret_file_patterns):
                if verbose:
                    logging.info(f"Skipping non-secret file: {file_path}")
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'rb') as f:
                        lines = [line.decode('latin-1') for line in f.readlines()]
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")
                    continue

            for line_num, line in enumerate(lines, 1):
                for pattern in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'line_content': line.strip(),
                            'pattern': pattern
                        })
                        break

    return issues
