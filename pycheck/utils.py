def highlight_issues(issues: List[Dict[str, Any]]) -> None:
    """
    Display found issues in a formatted way.
    
    Args:
        issues (List[Dict[str, Any]]): List of security issues
    """
    print("\nSecurity Issues Found:")
    print("=" * 50)
    for issue in issues:
        print(f"File: {issue['file']}")
        print(f"Line {issue['line']}: {issue['line_content']}")
        print(f"Pattern: {issue['pattern']}")
        print("-" * 50)
