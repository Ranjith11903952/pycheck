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
        List[Dict[str, Any]]: A list of issues found, each represented as a dictionary.
    """
    issues = []

    # Load sensitive patterns from environment variables or a config file
    sensitive_patterns = [
        r'API_?KEY\s*[:=]\s*["\']?[^"\'\s]+["\']?',  # Matches API_KEY="value", API_KEY=value, or "API_KEY": "value"
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

    # Patterns to exclude (e.g., comments, docstrings, etc.)
    exclude_patterns = [
        r'^\s*#',  # Python comments
        r'^\s*//',  # JavaScript/Java/C++ comments
        r'^\s*/\*',  # Start of multi-line comments
        r'\*/',  # End of multi-line comments
        r'^\s*[\'\"]{3}',  # Python docstrings
        r'@[\w\d_]+',  # JavaScript doc tags (e.g., @param, @return)
        r'\b(?:TODO|FIXME|XXX|HACK)\b',  # Common code annotations
        r'ace\.define',  # Exclude ACE editor patterns
        r'regex:"',  # Exclude regex patterns in JavaScript
        r'showUsername\s*:',  # Exclude showUsername in JavaScript
        r'userpic__username\s*:',  # Exclude userpic__username in JavaScript
    ]

    # Supported file extensions
    supported_extensions = (
        '.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go', '.rs', '.ts',  # Code files
        '.env', '.json', '.yaml', '.yml', '.ini', '.cfg', '.xml', '.toml', '.properties'  # Config files
    )

    # Files to exclude (e.g., minified JavaScript files)
    exclude_files = [
        r'\.min\.js$',  # Minified JavaScript files
        r'\.min\.css$',  # Minified CSS files
    ]

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip minified files
            if any(re.search(pattern, file) for pattern in exclude_files):
                if verbose:
                    logging.info(f"Skipping minified file: {file_path}")
                continue

            if file.endswith(supported_extensions):
                logging.info(f"Scanning file: {file_path}")
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

                in_comment_block = False  # Track multi-line comments and docstrings
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
                                'line_content': line.strip()
                            })
                            break  # Stop checking other patterns if a match is found

    return issues


def save_results_to_file(issues: List[Dict[str, Any]], output_file: str = "scan_results.json"):
    """
    Saves the scan results to a file in JSON format.

    Args:
        issues (List[Dict[str, Any]]): The list of issues to save.
        output_file (str): The output file path.
    """
    import json
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(issues, f, indent=4)
        logging.info(f"Scan results saved to {output_file}")
    except (IOError, PermissionError) as e:
        logging.error(f"Error saving results to {output_file}: {e}")


if __name__ == "__main__":
    # Example usage
    directory_to_scan = "path/to/your/directory"
    verbose = False  # Set to True to print detailed logs for skipped files
    issues_found = scan_directory(directory_to_scan, verbose)

    if issues_found:
        logging.warning(f"Found {len(issues_found)} potential issues.")
        for issue in issues_found:
            logging.warning(f"Issue in {issue['file']}, line {issue['line']}: {issue['line_content']}")
        save_results_to_file(issues_found)
    else:
        logging.info("No issues found.")
