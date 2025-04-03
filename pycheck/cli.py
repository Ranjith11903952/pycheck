import argparse
from pycheck.scanner import scan_directory
from pycheck.utils import highlight_issues
from pycheck.scanner import scan_secret_files as scan_directory
def main():
    parser = argparse.ArgumentParser(description="Scan a directory for API keys, credentials, and other security issues.")
    parser.add_argument("directory", type=str, help="The directory to scan.")
    
    args = parser.parse_args()
    issues = scan_directory(args.directory)
    
    highlight_issues(issues)

if __name__ == "__main__":
    main()
