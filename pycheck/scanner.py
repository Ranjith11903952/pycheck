import os
import re
import logging
from typing import List, Dict, Any, Optional
import json
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecretMigrator:
    """Handles migration of secrets from source files to .env file"""
    
    def __init__(self):
        self.env_content = []
        self.backup_dir = ".secret_backups"
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_backup(self, file_path: str) -> str:
        """Create backup of original file"""
        backup_path = os.path.join(self.backup_dir, os.path.basename(file_path) + ".bak")
        with open(file_path, 'r') as src, open(backup_path, 'w') as dst:
            dst.write(src.read())
        return backup_path
    
    def migrate_secret(self, file_path: str, line_num: int, line_content: str, pattern: str) -> bool:
        """
        Extract secret from line and prepare for .env migration
        Returns True if migration was successful
        """
        try:
            # Extract the key and value
            match = re.search(pattern, line_content, re.IGNORECASE)
            if not match:
                return False
            
            # Get the full matched string
            full_match = match.group(0)
            
            # Extract key and value parts
            if ':=' in full_match:
                key_part, value_part = full_match.split(':=', 1)
            elif '=' in full_match:
                key_part, value_part = full_match.split('=', 1)
            elif ':' in full_match:
                key_part, value_part = full_match.split(':', 1)
            else:
                return False
            
            # Clean up the key and value
            key = key_part.strip()
            value = value_part.strip().strip('\'"')
            
            # Add to .env content
            self.env_content.append(f"{key}={value}")
            return True
            
        except Exception as e:
            logging.error(f"Error migrating secret: {str(e)}")
            return False
    
    def write_env_file(self, directory: str) -> str:
        """Write collected secrets to .env file"""
        env_path = os.path.join(directory, ".env")
        if not self.env_content:
            return ""
        
        with open(env_path, 'w') as f:
            f.write("# Auto-generated .env file\n")
            f.write("# DO NOT COMMIT THIS FILE TO VERSION CONTROL!\n\n")
            f.write("\n".join(self.env_content))
        
        logging.warning(f"Created new .env file at {env_path}")
        logging.warning("REMEMBER TO ADD .env TO YOUR .gitignore!")
        return env_path

class SecretScanner(SecretMigrator):
    """Enhanced scanner with secret migration capabilities"""
    
    def __init__(self):
        super().__init__()
        # [Previous pattern definitions remain the same...]
        # ... (keep all the sensitive patterns and config file patterns from earlier)

    def prompt_user(self, file_path: str, issue: Dict[str, Any]) -> bool:
        """Ask user if they want to migrate the found secret"""
        print(f"\nFound potential secret in {file_path}:")
        print(f"Line {issue['line']}: {issue['line_content']}")
        print(f"Pattern matched: {issue['pattern']}")
        
        while True:
            response = input("Do you want to migrate this to .env? [y/n]: ").lower()
            if response in ('y', 'yes'):
                return True
            elif response in ('n', 'no'):
                return False
            else:
                print("Please answer 'y' or 'n'")

    def modify_source_file(self, file_path: str, issues: List[Dict[str, Any]]) -> bool:
        """
        Modify source file to remove secrets that were migrated to .env
        Returns True if modifications were made
        """
        # Create backup first
        backup_path = self.create_backup(file_path)
        logging.info(f"Created backup at {backup_path}")
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            modified = False
            for issue in sorted(issues, key=lambda x: x['line'], reverse=True):
                line_idx = issue['line'] - 1
                if 0 <= line_idx < len(lines):
                    # Replace the line with a comment or empty line
                    lines[line_idx] = f"# Removed secret: {lines[line_idx].strip()}\n"
                    modified = True
            
            if modified:
                with open(file_path, 'w') as f:
                    f.writelines(lines)
                logging.warning(f"Modified source file: {file_path}")
            
            return modified
            
        except Exception as e:
            logging.error(f"Failed to modify {file_path}: {str(e)}")
            return False

    def scan_and_migrate(self, directory: str, interactive: bool = True) -> Dict[str, Any]:
        """
        Scan directory and optionally migrate secrets to .env
        Returns dictionary with scan results and migration status
        """
        results = {
            'scanned_files': 0,
            'secrets_found': 0,
            'secrets_migrated': 0,
            'modified_files': [],
            'env_file_created': None
        }
        
        # First pass: scan and collect all issues
        all_issues = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_config_file(file):
                    results['scanned_files'] += 1
                    file_issues = self.scan_file(file_path)
                    if file_issues:
                        all_issues.extend(file_issues)
                        results['secrets_found'] += len(file_issues)
        
        if not all_issues:
            return results
        
        # Second pass: handle migration if secrets found
        files_to_modify = {}
        for issue in all_issues:
            file_path = issue['file']
            
            if interactive:
                migrate = self.prompt_user(file_path, issue)
            else:
                migrate = True  # auto-migrate in non-interactive mode
            
            if migrate:
                if self.migrate_secret(file_path, issue['line'], issue['line_content'], issue['pattern']):
                    results['secrets_migrated'] += 1
                    if file_path not in files_to_modify:
                        files_to_modify[file_path] = []
                    files_to_modify[file_path].append(issue)
        
        # Modify source files to remove migrated secrets
        for file_path, issues in files_to_modify.items():
            if self.modify_source_file(file_path, issues):
                results['modified_files'].append(file_path)
        
        # Create .env file if any secrets were migrated
        if self.env_content:
            env_path = self.write_env_file(directory)
            results['env_file_created'] = env_path
        
        return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Secret scanner and migrator")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--auto", action="store_true", help="Automatically migrate without prompts")
    parser.add_argument("--output", help="JSON output file", default="scan_results.json")
    args = parser.parse_args()
    
    scanner = SecretScanner()
    results = scanner.scan_and_migrate(args.directory, interactive=not args.auto)
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\nScan Summary:")
    print(f"Scanned files: {results['scanned_files']}")
    print(f"Secrets found: {results['secrets_found']}")
    print(f"Secrets migrated: {results['secrets_migrated']}")
    print(f"Modified files: {len(results['modified_files'])}")
    if results['env_file_created']:
        print(f"Created .env file at: {results['env_file_created']}")
        print("\nIMPORTANT: Add this to your .gitignore:")
        print(f"echo '\n# Secret scanner\\.env' >> .gitignore")

if __name__ == "__main__":
    main()
