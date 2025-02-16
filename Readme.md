
## Project setup

1) Install the requirements in your python venv:
```python
pip install -r requirements.txt
```

2) Run the following command to start the test flask site (running on port: `5000`) open it in your browser (optional): 

``` bash
cd Website
pip install flask
python test_app.py
```

2) Run the following command to test the vulnerabilities
```py
python scanner.py --url http://127.0.0.1:5000 --config config/scanner_config.json --output results/scan_results.json
```

3) Find the vulnerability results in the `scan_results.json` file in you `results/` folder in the root directory.

### File structure:
```
Adv web-vulnerability-scanner/
├── core/
│   ├── __init__.py
│   ├── base_scanner.py
│   └── utils.py
├── attacks/
│   ├── __init__.py
│   ├── injection/
│   │   ├── __init__.py
│   │   ├── sql_injection.py
│   │   ├── nosql_injection.py
│   │   ├── ldap_injection.py
│   │   └── xxe_injection.py
│   ├── xss/
│   │   ├── __init__.py
│   │   ├── stored_xss.py
│   │   ├── reflected_xss.py
│   │   └── dom_xss.py
│   ├── authentication/
│   │   ├── __init__.py
│   │   ├── brute_force.py
│   │   ├── session_hijacking.py
│   │   └── password_reset.py
│   ├── access_control/
│   │   ├── __init__.py
│   │   ├── idor.py
│   │   └── privilege_escalation.py
│   ├── file_handling/
│   │   ├── __init__.py
│   │   ├── file_upload.py
│   │   └── file_inclusion.py
│   └── advanced/
│       ├── __init__.py
│       ├── ssrf.py
│       ├── websocket.py
│       └── api_abuse.py
├── payloads/
│   ├── sql_injection.txt
│   ├── xss.txt
│   └── command_injection.txt
├── results/
│   └── .gitkeep
├── config/
│   └── scanner_config.json
├── Website/
│   ├── test_app.py
│   └── test.db
├── requirements.txt
├── scanner.py
└── README.md
```