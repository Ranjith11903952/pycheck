def highlight_issues(issues):
    for issue in issues:
        print(f"File: {issue['file']}")
        print(f"Line: {issue['line']}")
        print(f"Content: {issue['line_content']}")
        print(f"Pattern: {issue['pattern']}")
        print("-" * 40)