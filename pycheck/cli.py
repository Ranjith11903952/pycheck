import argparse
from pycheck.scanner import scan_directory
from pycheck.utils import highlight_issues

def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory for API keys, credentials, and other security issues."
    )
    parser.add_argument("directory", type=str, help="The directory to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    issues = scan_directory(args.directory, verbose=args.verbose)
    
    if issues:
        highlight_issues(issues)
    else:
        print("No security issues found.")

if __name__ == "__main__":
    main()
