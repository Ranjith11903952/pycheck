from colorama import Fore, Style
import emoji
import time
import sys

def highlight_issues(issues):
    if issues:
        print(Fore.RED + "Potential security issues found:" + Style.RESET_ALL)
        for issue in issues:
            print(Fore.RED + f"File: {issue['file']}" + Style.RESET_ALL)
            print(f"Line: {issue['line']}")
            print(f"Content: {issue['line_content']}")
            print("-" * 40)
        print(Fore.RED + f"Found {len(issues)} potential security issues." + Style.RESET_ALL)
    else:
        # Animated thumbs-up gesture
        print(Fore.GREEN + "No security issues found. All good! " + Style.RESET_ALL, end="")
        for _ in range(3):  # Repeat the animation 3 times
            sys.stdout.write(emoji.emojize(":thumbs_up:"))  # Display thumbs-up emoji
            sys.stdout.flush()
            time.sleep(0.5)  # Pause for 0.5 seconds
            sys.stdout.write("\b \b")  # Erase the emoji
            sys.stdout.flush()
            time.sleep(0.5)  # Pause for 0.5 seconds
        print(emoji.emojize(":thumbs_up:"))  # Display the final thumbs-up emoji
