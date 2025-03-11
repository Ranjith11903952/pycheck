import os
import re

def scan_directory(directory):
    issues = []
    key_patterns = [
        r'API_?KEY', r'SECRET_?KEY', r'ACCESS_?KEY', r'TOKEN',
        r'PASSWORD', r'CREDENTIALS', r'AUTH_?KEY', r'PRIVATE_?KEY',
        r'USERNAME', r'USER_?NAME', r'DB_?NAME', r'DB_?PASSWORD',
        r'DB_?HOST', r'DATABASE_?URL', r'CONNECTION_?STRING',
        r'AWS_?ACCESS_?KEY', r'AWS_?SECRET_?KEY', r'SSH_?KEY',
        r'PRIVATE_?KEY', r'PUBLIC_?KEY', r'ENCRYPTION_?KEY'
    ]
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.env', '.json', '.yaml', '.yml', '.txt', '.ini', '.cfg')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line_num, line in enumerate(lines, 1):
                        for pattern in key_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                issues.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'line_content': line.strip()
                                })
    return issues
