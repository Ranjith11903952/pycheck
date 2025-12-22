import os
import re
import sys
from typing import List, Dict, Any, Optional, Set, Tuple

# Simple color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def load_ignore_patterns(directory: str) -> List[str]:
    """Load patterns to ignore from .pycheckignore file"""
    ignore_file = os.path.join(directory, '.pycheckignore')
    if os.path.exists(ignore_file):
        with open(ignore_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

def is_line_commented(line: str) -> bool:
    """Check if a line is commented out"""
    trimmed = line.strip()
    return trimmed.startswith(('#', '//', '/*', '*/', '<!--', '-->'))

def get_secret_patterns() -> List[str]:
    """Return patterns for secret detection"""
    return [
        # URLs
        r'^\s*[^#]*\b\w+\s*[=:]\s*["\'](?:https?|ftp|ws|wss)://[^"\']+["\']',
        
        # Secret variables
        r'^\s*[^#]*\b(?:[A-Z_]+(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL))\b\s*[=:]\s*["\'][^"\']+["\']',
        
        # URL/Endpoint variables
        r'^\s*[^#]*\b(?:[A-Z_]+(?:URL|URI|ENDPOINT|HOST|SERVER))\b\s*[=:]\s*["\'][^"\']+["\']',
        
        # Database configs
        r'^\s*[^#]*\b(?:DATABASE_|DB_)?(?:URL|HOST|NAME|USER|PASSWORD|PORT)\b\s*[=:]\s*["\'][^"\']+["\']',
        
        # Social auth
        r'^\s*[^#]*SOCIAL_AUTH_[A-Z_]+_(?:KEY|SECRET)\b\s*[=:]\s*["\'][^"\']+["\']',
        
        # Django secret key
        r'^\s*[^#]*SECRET_KEY\s*[=:]\s*["\'][^"\']+["\']',
        
        # API keys
        r'^\s*[^#]*\b[A-Z_]*API(?:_KEY|_SECRET)?\b\s*[=:]\s*["\'][^"\']+["\']',
    ]

def is_secret_line(line: str, pattern: str) -> bool:
    """Check if a line contains a secret"""
    line_stripped = line.strip()
    
    if not line_stripped or is_line_commented(line_stripped):
        return False
    
    if 'os.environ' in line or 'os.getenv' in line or 'environ.get' in line:
        return False
    
    if re.search(pattern, line, re.IGNORECASE):
        return True
    
    return False

def extract_variable_name(line: str) -> Tuple[str, str]:
    """Extract variable name and value from a line"""
    line = line.strip()
    
    # Match patterns like: VAR = "value" or VAR: "value"
    match = re.match(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["\']([^"\']*)["\']', line)
    if match:
        return match.group(1), match.group(2)
    
    # Match patterns like: VAR = ["url1", "url2"]
    match = re.match(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*\[.*\]', line)
    if match:
        return match.group(1), ""
    
    return "", ""

def get_env_suggestion(line: str) -> str:
    """Generate os.environ suggestion for a line"""
    var_name, value = extract_variable_name(line)
    
    if not var_name:
        return "# " + line.strip()
    
    # Generate environment variable name suggestion
    env_var = var_name.upper().replace("-", "_")
    
    # Different patterns based on variable name
    if "PASSWORD" in var_name.upper() or "SECRET" in var_name.upper() or "KEY" in var_name.upper():
        return f"{var_name} = os.environ.get('{env_var}')"
    elif "URL" in var_name.upper() or "URI" in var_name.upper() or "ENDPOINT" in var_name.upper():
        return f"{var_name} = os.environ.get('{env_var}', '{value}')  # Default value shown"
    else:
        return f"{var_name} = os.environ.get('{env_var}', '{value}')"

def get_fix_suggestions(line: str) -> List[str]:
    """Get multiple fix suggestions for a line"""
    suggestions = []
    
    # 1. Simple comment
    suggestions.append("# " + line.strip())
    
    # 2. os.environ suggestion
    env_suggestion = get_env_suggestion(line)
    if env_suggestion:
        suggestions.append(env_suggestion)
    
    # 3. Remove the line (if it's not critical)
    if "SECRET_KEY" not in line.upper() and "PASSWORD" not in line.upper():
        suggestions.append("# " + line.strip() + "  # REMOVE THIS LINE AND USE ENVIRONMENT VARIABLES")
    
    return suggestions

def get_config_files(directory: str, extensions: Optional[List[str]] = None) -> List[str]:
    """Get configuration files only"""
    if extensions is None:
        extensions = ['.py', '.yml', '.yaml', '.env']
    
    config_names = ['settings', 'config', 'configuration', 'local', 'prod', 'dev', 'staging']
    
    all_files = []
    
    if os.path.isfile(directory):
        if any(directory.endswith(ext) for ext in extensions):
            all_files.append(directory)
    
    elif os.path.isdir(directory):
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Check if it's a config file
                    if any(name in file_lower for name in config_names) or file in ['.env', '.env.local']:
                        all_files.append(file_path)
    
    return all_files

def show_issues_summary(issues: List[Dict[str, Any]], directory: str) -> None:
    """Show summary of found issues"""
    active_issues = [i for i in issues if not i.get('commented', False)]
    
    if not active_issues:
        print(f"\n{Colors.GREEN}✅ No security issues found!{Colors.RESET}")
        return
    
    print(f"\n{Colors.RED}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}🚨 FOUND {len(active_issues)} SECURITY ISSUES{Colors.RESET}")
    print(f"{Colors.RED}{'='*60}{Colors.RESET}")
    
    # Group by file
    issues_by_file = {}
    for issue in active_issues:
        file_path = issue['file']
        if file_path not in issues_by_file:
            issues_by_file[file_path] = []
        issues_by_file[file_path].append(issue)
    
    for file_path, file_issues in issues_by_file.items():
        print(f"\n{Colors.BOLD}📄 {os.path.relpath(file_path, directory)}{Colors.RESET}")
        for issue in file_issues:
            print(f"  {Colors.RED}Line {issue['line']}:{Colors.RESET} {issue['content'][:80]}...")

def show_preview(issues: List[Dict[str, Any]]) -> None:
    """Show preview of changes with suggestions"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}📝 PREVIEW OF CHANGES:{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    for issue in issues[:5]:  # Show first 5
        print(f"\n{Colors.YELLOW}File: {os.path.basename(issue['file'])} - Line {issue['line']}{Colors.RESET}")
        print(f"{Colors.RED}BEFORE:{Colors.RESET} {issue['content']}")
        print(f"{Colors.GREEN}SUGGESTIONS:{Colors.RESET}")
        
        suggestions = get_fix_suggestions(issue['content'])
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {i}. {suggestion}")
    
    if len(issues) > 5:
        print(f"\n{Colors.YELLOW}... and {len(issues) - 5} more issues{Colors.RESET}")

def fix_with_choice(issues: List[Dict[str, Any]], choice: str = "comment") -> Set[str]:
    """Fix issues based on user choice"""
    modified_files = set()
    
    # Group by file
    issues_by_file = {}
    for issue in issues:
        file_path = issue['file']
        if file_path not in issues_by_file:
            issues_by_file[file_path] = []
        issues_by_file[file_path].append(issue)
    
    for file_path, file_issues in issues_by_file.items():
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Sort by line number descending
            file_issues.sort(key=lambda x: x['line'], reverse=True)
            
            for issue in file_issues:
                line_num = issue['line'] - 1
                if 0 <= line_num < len(lines):
                    original = lines[line_num]
                    
                    if choice == "comment":
                        # Simple comment
                        leading_spaces = len(original) - len(original.lstrip())
                        lines[line_num] = ' ' * leading_spaces + '# ' + original.lstrip()
                    
                    elif choice == "environ":
                        # Replace with os.environ
                        suggestion = get_env_suggestion(original.rstrip())
                        leading_spaces = len(original) - len(original.lstrip())
                        lines[line_num] = ' ' * leading_spaces + suggestion + '\n'
                    
                    elif choice == "remove":
                        # Remove the line
                        lines[line_num] = '\n'
            
            # Write back
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            modified_files.add(file_path)
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error fixing {file_path}: {e}{Colors.RESET}")
    
    return modified_files

def show_detailed_suggestions(issues: List[Dict[str, Any]]) -> None:
    """Show detailed suggestions for manual fixing"""
    print(f"\n{Colors.MAGENTA}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}🔧 DETAILED FIXING SUGGESTIONS:{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*60}{Colors.RESET}")
    
    for issue in issues:
        print(f"\n{Colors.BOLD}📄 {os.path.basename(issue['file'])}:{Colors.RESET} Line {issue['line']}")
        print(f"{Colors.RED}Original:{Colors.RESET} {issue['content']}")
        print(f"{Colors.GREEN}Suggestions:{Colors.RESET}")
        
        suggestions = get_fix_suggestions(issue['content'])
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {Colors.CYAN}{i}.{Colors.RESET} {suggestion}")
        
        print(f"\n{Colors.YELLOW}Recommended approach:{Colors.RESET}")
        if "SECRET_KEY" in issue['content'] or "PASSWORD" in issue['content']:
            print("  • Use option 2 (os.environ) for production")
            print("  • Set the environment variable in your deployment")
            print("  • For Django: SECRET_KEY = os.environ.get('SECRET_KEY')")
        elif "URL" in issue['content'] or "ENDPOINT" in issue['content']:
            print("  • Use option 2 with a default for development")
            print("  • Example: API_URL = os.environ.get('API_URL', 'http://localhost:8000')")
        else:
            print("  • Use option 1 to comment it out temporarily")
            print("  • Or option 2 to use environment variables")
        
        print(f"{Colors.MAGENTA}{'-'*40}{Colors.RESET}")

def scan_directory(
    directory: str,
    verbose: bool = False,
    auto_fix: bool = False,
    clean_commented: bool = False,
    extensions: Optional[List[str]] = None,
    no_prompt: bool = False
) -> List[Dict[str, Any]]:
    """
    Scan configuration files for hardcoded secrets
    
    Args:
        directory: Path to scan
        verbose: Show detailed output
        auto_fix: Automatically fix issues
        clean_commented: Remove commented secrets
        extensions: File extensions to scan
        no_prompt: Skip user prompts
    
    Returns:
        List of found issues
    """
    issues = []
    patterns = get_secret_patterns()
    ignore_patterns = load_ignore_patterns(directory)
    
    # Get files to scan
    files = get_config_files(directory, extensions)
    
    if not files:
        print(f"{Colors.YELLOW}⚠️ No configuration files found{Colors.RESET}")
        return []
    
    if verbose:
        print(f"{Colors.BLUE}📁 Scanning {len(files)} configuration files...{Colors.RESET}")
    
    # Scan files
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.splitlines(), 1):
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Skip already commented lines
                if is_line_commented(line.strip()):
                    continue
                
                # Check each pattern
                for pattern in patterns:
                    if is_secret_line(line, pattern):
                        issues.append({
                            'file': file_path,
                            'line': line_num,
                            'content': line.strip(),
                            'pattern': pattern
                        })
                        break  # Only count once per line
        
        except Exception as e:
            if verbose:
                print(f"{Colors.YELLOW}⚠️ Could not scan {file_path}: {e}{Colors.RESET}")
    
    # Show results
    active_issues = [i for i in issues if not i.get('commented', False)]
    
    if active_issues:
        show_issues_summary(active_issues, directory)
        
        if not auto_fix and not no_prompt:
            # Ask user what to do
            print(f"\n{Colors.BOLD}What would you like to do?{Colors.RESET}")
            print(f"{Colors.CYAN}1.{Colors.RESET} Show preview and choose fix method")
            print(f"{Colors.CYAN}2.{Colors.RESET} Auto-fix with os.environ (recommended for production)")
            print(f"{Colors.CYAN}3.{Colors.RESET} Show detailed suggestions")
            
            choice = input(f"\n{Colors.YELLOW}Enter choice (1-3): {Colors.RESET}").strip()
            
            if choice == '1':
                show_preview(active_issues)
                print(f"\n{Colors.BOLD}Choose fix method:{Colors.RESET}")
                print(f"{Colors.CYAN}1.{Colors.RESET} Comment out (temporary fix)")
                print(f"{Colors.CYAN}2.{Colors.RESET} Replace with os.environ (production ready)")
                print(f"{Colors.CYAN}3.{Colors.RESET} Remove lines")
                
                fix_choice = input(f"\n{Colors.YELLOW}Enter fix method (1-3): {Colors.RESET}").strip()
                
                if fix_choice == '1':
                    modified = fix_with_choice(active_issues, "comment")
                    print(f"\n{Colors.GREEN}✅ Commented {len(active_issues)} issues in {len(modified)} files{Colors.RESET}")
                    print(f"{Colors.YELLOW}Note: Remember to set environment variables for production{Colors.RESET}")
                
                elif fix_choice == '2':
                    modified = fix_with_choice(active_issues, "environ")
                    print(f"\n{Colors.GREEN}✅ Replaced {len(active_issues)} issues with os.environ in {len(modified)} files{Colors.RESET}")
                    print(f"{Colors.YELLOW}Next steps:{Colors.RESET}")
                    print(f"  1. Set environment variables:")
                    for issue in active_issues[:3]:  # Show first 3 variables
                        var_name, _ = extract_variable_name(issue['content'])
                        if var_name:
                            print(f"     export {var_name.upper().replace('-', '_')}=your_value_here")
                    print(f"  2. Test your application with the new environment variables")
                
                elif fix_choice == '3':
                    modified = fix_with_choice(active_issues, "remove")
                    print(f"\n{Colors.GREEN}✅ Removed {len(active_issues)} lines from {len(modified)} files{Colors.RESET}")
                    print(f"{Colors.YELLOW}Warning: Make sure to set these values elsewhere (env vars, config files){Colors.RESET}")
                
                else:
                    print(f"{Colors.YELLOW}⚠️ No fix applied{Colors.RESET}")
            
            elif choice == '2':
                # Auto-fix with os.environ
                confirm = input(f"\n{Colors.YELLOW}Replace all with os.environ? (yes/no): {Colors.RESET}").lower()
                if confirm in ('y', 'yes'):
                    modified = fix_with_choice(active_issues, "environ")
                    print(f"\n{Colors.GREEN}✅ Replaced {len(active_issues)} issues with os.environ{Colors.RESET}")
                    
                    # Show environment variables to set
                    print(f"\n{Colors.BOLD}📋 Environment variables to set:{Colors.RESET}")
                    env_vars = set()
                    for issue in active_issues:
                        var_name, _ = extract_variable_name(issue['content'])
                        if var_name:
                            env_vars.add(var_name.upper().replace('-', '_'))
                    
                    for env_var in sorted(env_vars):
                        print(f"  {Colors.CYAN}{env_var}{Colors.RESET}=your_value_here")
                    
                    print(f"\n{Colors.YELLOW}Add these to your .env file or deployment environment{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}⚠️ No changes made{Colors.RESET}")
            
            elif choice == '3':
                show_detailed_suggestions(active_issues)
            
            else:
                print(f"{Colors.YELLOW}⚠️ No action taken{Colors.RESET}")
        
        elif auto_fix:
            # Auto-fix mode (use os.environ by default)
            modified = fix_with_choice(active_issues, "environ")
            print(f"\n{Colors.GREEN}✅ Auto-fixed {len(active_issues)} issues with os.environ{Colors.RESET}")
    
    else:
        print(f"\n{Colors.GREEN}✅ No security issues found!{Colors.RESET}")
    
    return issues

def test_scanner():
    """Test the scanner with various examples"""
    test_cases = [
        "SECRET_KEY = 'django-insecure-hardcoded-key-12345'",
        "DATABASE_PASSWORD = 'mypassword123'",
        "API_URL = 'https://api.example.com'",
        "SOCIAL_AUTH_GITHUB_SECRET = 'github-secret-here'",
        "DEBUG = True",
        "ALLOWED_HOSTS = ['localhost', '127.0.0.1']",
    ]
    
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}🧪 TESTING SCANNER SUGGESTIONS{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    for test_line in test_cases:
        print(f"\n{Colors.BOLD}Test:{Colors.RESET} {test_line}")
        if is_secret_line(test_line, get_secret_patterns()[0]):
            print(f"{Colors.RED}Detected as secret{Colors.RESET}")
            suggestions = get_fix_suggestions(test_line)
            print(f"{Colors.GREEN}Suggestions:{Colors.RESET}")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"  {i}. {suggestion}")
        else:
            print(f"{Colors.GREEN}✅ Safe line{Colors.RESET}")

if __name__ == "__main__":
    # Simple test
    test_scanner()
