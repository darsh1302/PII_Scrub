---
trigger: onSave
fileMatch: "**/*.py"
---

# No Hardcoded API Keys

When a Python file is saved, scan it for any hardcoded API keys or secrets. Look for patterns like:
- Strings starting with "sk-"
- Variables named `api_key`, `secret`, `token` assigned to string literals
- Any OpenAI key patterns

If found, warn the user and suggest using `os.getenv()` or `python-dotenv` instead.
