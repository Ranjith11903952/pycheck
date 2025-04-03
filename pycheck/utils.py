from typing import List, Dict, Any

def highlight_issues(issues: List[Dict[str, Any]]) -> None:
    """
    Display found issues in a formatted way.
    """
    print("\nSecurity Issues Found:")
    print("=" * 50)
    for issue in issues:
        print(f"File: {issue['file']}")
        print(f"Line {issue['line']}: {issue['line_content']}")
        print("-" * 50)
