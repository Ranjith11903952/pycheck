import re

# Your code sample
test_code = '''
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", default="127.0.0.1").split(":")
# CSRF_TRUSTED_ORIGINS = ["https://stage.augmatrix.ai", "https://prod.augmatrix.ai"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ["ranjith"],
        "USER": os.environ["USER_NAME"],
        "PASSWORD": os.environ["PASSWORD"],
#         "HOST": "https://mysql.com",
        "PORT": "8080",
    }
}

# SOCIAL_AUTH_GITHUB_KEY = "dfsdkfhbaspidufbsaidhfbasjlahdbasjhlfdbas"
SOCIAL_AUTH_GITHUB_SECRET = os.environ.get("SOCIAL_AUTH_GITHUB_SECRET")
'''

# Test patterns
patterns = [
    # Hardcoded URLs
    (r'\b(?:https?|ftp|ws|wss)://[^\s\'\"]+', 'Hardcoded URL'),
    
    # Variables with _URL, _KEY, etc. that are hardcoded
    (r'(?<!#)\b["\']?[A-Za-z0-9_]*_(?:URL|URI|ENDPOINT|HOST|SERVER)["\']?\s*[:=]\s*["\'](?!os\.environ|os\.getenv)[^"\']+["\']', 'Hardcoded URL variable'),
    
    # Hardcoded keys/secrets
    (r'(?<!#)\b["\']?[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)["\']?\s*[:=]\s*["\'](?!os\.environ|os\.getenv)[^"\']+["\']', 'Hardcoded secret'),
    
    # Database hardcoded values
    (r'(?<!#)\b["\']?(?:DB|DATABASE)_?(?:HOST|NAME|USER|PORT|URI|URL)["\']?\s*[:=]\s*["\'](?!os\.environ|os\.getenv)[^"\']+["\']', 'Hardcoded DB config'),
    
    # Array with hardcoded values
    (r'(?:ALLOWED_HOSTS|ALLOWED_CIDR_NETS|CSRF_TRUSTED_ORIGINS)\s*=\s*\[[^\]]*["\'][^\]]+["\']', 'Hardcoded array'),
]

print("Testing patterns on your code:")
print("=" * 50)

for pattern, description in patterns:
    matches = re.finditer(pattern, test_code)
    for match in matches:
        print(f"🚨 {description}: {match.group()}")

if not any(re.finditer(pattern, test_code) for pattern, _ in patterns):
    print("❌ No matches found - patterns need adjustment")