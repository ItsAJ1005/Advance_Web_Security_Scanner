import re

# Common regex patterns used across scanners
CSRF_PATTERN = re.compile(r'csrf|xsrf|token', re.I)
SQL_ERROR_PATTERN = re.compile(r'sql|mysql|sqlite|postgresql|oracle|database error', re.I)
XSS_PATTERN = re.compile(r'<script|javascript:|onerror=|onload=', re.I)
SENSITIVE_DATA_PATTERN = re.compile(r'password|secret|key|token|credential', re.I)
