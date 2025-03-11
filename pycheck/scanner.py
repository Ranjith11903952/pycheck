import os
import re

def scan_directory(directory):
    issues = []
    # Regex patterns to detect sensitive data
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
    
    # Supported file extensions
    supported_extensions = (
        '.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go', '.rs', '.ts',  # Code files
        '.env', '.json', '.yaml', '.yml', '.ini', '.cfg', '.xml', '.toml', '.properties'  # Config files
    )
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(supported_extensions):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line_num, line in enumerate(lines, 1):
                        for pattern in sensitive_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                issues.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'line_content': line.strip()
                                })
    return issues
