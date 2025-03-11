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
                    in_comment_block = False  # Track multi-line comments and docstrings
                    for line_num, line in enumerate(lines, 1):
                        # Skip lines that define regex patterns (e.g., r'API_?KEY')
                        if re.search(r'^\s*r[\'"]', line):
                            continue
                        
                        # Skip comment lines in Python, JavaScript, etc.
                        if re.search(r'^\s*#', line):  # Python, shell, etc.
                            continue
                        if re.search(r'^\s*//', line):  # JavaScript, Java, C++, etc.
                            continue
                        if re.search(r'^\s*/\*', line):  # Start of multi-line comment in JS, Java, etc.
                            in_comment_block = True
                        if in_comment_block:
                            if re.search(r'\*/', line):  # End of multi-line comment
                                in_comment_block = False
                            continue
                        
                        # Skip docstrings and multi-line strings in Python
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
