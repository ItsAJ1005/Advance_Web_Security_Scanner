web-vulnerability-scanner/
│
├── core/
│   ├── __init__.py
│   ├── base_scanner.py
│   └── utils.py
│
├── attacks/
│   ├── __init__.py
│   ├── injection/
│   │   ├── __init__.py
│   │   ├── sql_injection.py
│   │   ├── nosql_injection.py
│   │   ├── ldap_injection.py
│   │   └── xxe_injection.py
│   │
│   ├── xss/
│   │   ├── __init__.py
│   │   ├── stored_xss.py
│   │   ├── reflected_xss.py
│   │   └── dom_xss.py
│   │
│   ├── authentication/
│   │   ├── __init__.py
│   │   ├── brute_force.py
│   │   ├── session_hijacking.py
│   │   └── password_reset.py
│   │
│   ├── access_control/
│   │   ├── __init__.py
│   │   ├── idor.py
│   │   └── privilege_escalation.py
│   │
│   ├── file_handling/
│   │   ├── __init__.py
│   │   ├── file_upload.py
│   │   └── file_inclusion.py
│   │
│   └── advanced/
│       ├── __init__.py
│       ├── ssrf.py
│       ├── websocket.py
│       └── api_abuse.py
│
├── payloads/
│   ├── sql_injection.txt
│   ├── xss.txt
│   └── command_injection.txt
│
├── results/
│   └── .gitkeep
│
├── config/
│   └── scanner_config.json
│
├── requirements.txt
├── scanner.py
└── README.md