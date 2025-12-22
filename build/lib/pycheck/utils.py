from typing import List, Dict, Any

def highlight_issues(issues: List[Dict[str, Any]]) -> None:
    for issue in issues:
        print(f"File: {issue['file']}")
        print(f"Line {issue['line']}: {issue['content']}")  # Changed from 'line_content'
        print("-" * 50)
