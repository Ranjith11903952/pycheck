from colorama import Fore, Style

def highlight_issues(issues):
    if issues:
        print(Fore.RED + "Potential security issues found:" + Style.RESET_ALL)
        for issue in issues:
            print(Fore.RED + f"File: {issue['file']}" + Style.RESET_ALL)
            print(f"Line: {issue['line']}")
            print(f"Content: {issue['line_content']}")
            print(f"Pattern: {issue['pattern']}")
            print("-" * 40)
    else:
        print(Fore.GREEN + "No security issues found. All good!" + Style.RESET_ALL)
