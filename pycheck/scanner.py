import os
import re
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_secret_files(directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Scans a directory for configuration files that typically contain secrets.
    Focuses on files like settings.py, .env, config files, etc.

    Args:
        directory (str): The directory to scan.
        verbose (bool): If True, print detailed logs for skipped files.

    Returns:
        List[Dict[str, Any]]: A list of issues found, each represented as a dictionary.
    """
    issues = []

    # Sensitive patterns (same as before)
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

    # Patterns to exclude (same as before)
    exclude_patterns = [
        r'^\s*#',
        r'^\s*//',
        r'^\s*/\*',
        r'\*/',
        r'^\s*[\'\"]{3}',
        r'@[\w\d_]+',
        r'\b(?:TODO|FIXME|XXX|HACK)\b',
        r'ace\.define',
        r'regex:"',
        r'showUsername\s*:',
        r'userpic__username\s*:',
    ]

    # Focus only on configuration files that typically contain secrets
    secret_file_patterns = [
        # Python
        r'settings\.py$',
        r'config\.py$',
        r'secrets\.py$',
        r'local_settings\.py$',
        
        # Environment files
        r'\.env$',
        r'\.env\.local$',
        r'\.env\.dev$',
        r'\.env\.prod$',
        r'\.env\.example$',
        
        # Configuration files
        r'config\.json$',
        r'config\.yaml$',
        r'config\.yml$',
        r'configuration\.json$',
        r'appsettings\.json$',
        r'\.properties$',
        
        # Other common secret files
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
            
            # Check if file matches any of our secret file patterns
            if not any(re.search(pattern, file, re.IGNORECASE) for pattern in secret_file_patterns):
                if verbose:
                    logging.info(f"Skipping non-secret file: {file_path}")
                continue

            logging.info(f"Scanning secret file: {file_path}")
            try:
                # Try reading the file with UTF-8 encoding first
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                # If UTF-8 fails, try reading the file as binary
                try:
                    with open(file_path, 'rb') as f:
                        lines = [line.decode('latin-1') for line in f.readlines()]
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")
                    continue

            in_comment_block = False
            for line_num, line in enumerate(lines, 1):
                # Skip lines that match exclude patterns
                if any(re.search(pattern, line) for pattern in exclude_patterns):
                    continue

                # Skip multi-line comments and docstrings
                if re.search(r'^\s*/\*', line):  # Start of multi-line comment
                    in_comment_block = True
                if in_comment_block:
                    if re.search(r'\*/', line):  # End of multi-line comment
                        in_comment_block = False
                    continue
                if re.search(r'^\s*[\'\"]{3}', line):  # Start or end of docstring
                    in_comment_block = not in_comment_block
                    continue
                if in_comment_block:
                    continue

                # Check for sensitive data
                for pattern in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'line_content': line.strip(),
                            'pattern': pattern  # Add which pattern was matched
                        })
                        break  # Stop checking other patterns if a match is found

    return issues


def save_results_to_file(issues: List[Dict[str, Any]], output_file: str = "secret_scan_results.json"):
    """
    Saves the scan results to a file in JSON format.

    Args:
        issues (List[Dict[str, Any]]): The list of issues to save.
        output_file (str): The output file path.
    """
    import json
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(issues, f, indent=4, ensure_ascii=False)
        logging.info(f"Secret scan results saved to {output_file}")
    except (IOError, PermissionError) as e:
        logging.error(f"Error saving results to {output_file}: {e}")


if __name__ == "__main__":
    # Example usage
    directory_to_scan = "path/to/your/directory"
    verbose = False  # Set to True to print detailed logs for skipped files
    issues_found = scan_secret_files(directory_to_scan, verbose)

    if issues_found:
        logging.warning(f"Found {len(issues_found)} potential secrets in configuration files.")
        for issue in issues_found:
            logging.warning(f"Secret in {issue['file']}, line {issue['line']}: {issue['line_content']}")
        save_results_to_file(issues_found)
    else:
        logging.info("No secrets found in configuration files.")
