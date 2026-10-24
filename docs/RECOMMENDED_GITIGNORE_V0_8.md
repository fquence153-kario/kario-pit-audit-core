# Suggested future `.gitignore` amendments — manual review required

Review and merge relevant lines into your original `.gitignore` **without blindly overwriting it**. These patterns only affect untracked files, do not erase existing Git history, and cannot guarantee no confidential data is committed.

```gitignore
.venv/
venv/
__pycache__/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.sqlite
*.sqlite3
*.db
*.jsonl
*.csv
*.parquet
*.zip
*.7z
*.log
*.review.json
*.review.jsonl
outputs/
data/
private/
local_data/
customer_data/
secrets/
```

Public, individually reviewed synthetic fixtures should go in a deliberately allowlisted location. Simply naming data `synthetic` or assigning `OWNED_PRIVATE` does **not** certify its rights. `.gitignore` is a convenience, not a security boundary. Run a clean Git history audit prior to publication.
