#!/usr/bin/env python3
"""
CLI interface for pycheck - Security scanner for hardcoded secrets in configuration files
"""

import argparse
import sys
from pycheck.scanner import scan_directory, Colors

def main():
    parser = argparse.ArgumentParser(
        description='Scan Python configuration files for hardcoded secrets',
        epilog='Example: pycheck . --verbose\nExample: pycheck settings.py --auto-fix'
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Directory or file to scan (default: current directory)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed progress information'
    )
    
    parser.add_argument(
        '--auto-fix',
        action='store_true',
        help='Automatically comment out found secrets'
    )
    
    parser.add_argument(
        '--clean-commented',
        action='store_true',
        help='Remove already commented secrets'
    )
    
    parser.add_argument(
        '--no-prompt',
        action='store_true',
        help='Skip confirmation prompt for auto-fix'
    )
    
    parser.add_argument(
        '--extensions',
        nargs='+',
        default=['.py', '.yml', '.yaml', '.env'],
        help='File extensions to scan (default: .py .yml .yaml .env)'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run scanner tests'
    )
    
    parser.add_argument(
        '--test-comments',
        action='store_true',
        help='Test comment detection'
    )
    
    parser.add_argument(
        '--all-files',
        action='store_true',
        help='Scan all files (not just configuration files)'
    )
    
    args = parser.parse_args()
    
    # Run tests if requested
    if args.test:
        try:
            from pycheck.scanner import test_scanner
            test_scanner()
            sys.exit(0)
        except ImportError as e:
            print(f"{Colors.RED}❌ Error importing test module: {e}{Colors.RESET}")
            sys.exit(1)
    
    if args.test_comments:
        try:
            from pycheck.scanner import test_comment_detection
            test_comment_detection()
            sys.exit(0)
        except ImportError as e:
            print(f"{Colors.RED}❌ Error importing test module: {e}{Colors.RESET}")
            sys.exit(1)
    
    try:
        # Convert auto_fix based on no_prompt flag
        auto_fix = args.auto_fix or args.no_prompt
        
        print(f"{Colors.CYAN}🔍 pycheck - Security Scanner for Configuration Files{Colors.RESET}")
        print(f"{Colors.BLUE}Scanning: {args.path}{Colors.RESET}")
        
        issues = scan_directory(
            directory=args.path,
            verbose=args.verbose,
            auto_fix=auto_fix,
            clean_commented=args.clean_commented,
            extensions=args.extensions
        )
        
        # Exit with appropriate code
        active_issues = [issue for issue in issues if not issue.get('commented', False)]
        
        if active_issues:
            print(f"\n{Colors.RED}❌ Found {len(active_issues)} active security issues{Colors.RESET}")
            sys.exit(1)  # Exit with error code if issues found
        else:
            print(f"\n{Colors.GREEN}✅ No active security issues found{Colors.RESET}")
            sys.exit(0)  # Exit successfully if no issues
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Scan interrupted by user{Colors.RESET}")
        sys.exit(130)
    except FileNotFoundError as e:
        print(f"{Colors.RED}❌ File not found: {e}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
        import traceback
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
