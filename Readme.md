**Description:**

Hello and welcome to the Advanced Web Vulnerability Scanner project!

This description is intended to provide a detailed overview of our project’s architecture, core functionalities, and contribution guidelines. Whether you’re planning to fix a bug, add a new feature, or simply learn from our codebase, this document will help you understand how the project is organized and how everything fits together.

---

## 1. Project Overview

The Advanced Web Vulnerability Scanner is a modular, Python-based tool designed to scan websites for common web vulnerabilities. At present, the project implements scanners for SQL Injection and Cross-Site Scripting (XSS), but its architecture allows for easy extension to include additional vulnerability types such as NoSQL injection, LDAP injection, SSRF, and more.

---

## 2. File Structure Breakdown

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

- **`core/`**  
  - **`base_scanner.py`**:  
    Contains the abstract `BaseScanner` class, which serves as the foundation for all vulnerability scanners. It manages HTTP requests (with rate limiting), logging, and the overall scanning workflow.
    
  - **`utils.py`**:  
    Houses utility classes and functions such as `URLUtils` (for URL normalization and validation) and `RequestUtils` (for HTML form extraction using BeautifulSoup).

- **`attacks/`**  
  Contains the vulnerability scanning modules grouped by category:
  - **`injection/`**:  
    - **`sql_injection.py`**:  
      Implements the SQL Injection scanner using various techniques (error-based, boolean-based, and time-based) to detect potential SQL injection vulnerabilities.
    - **Other files** (e.g., `nosql_injection.py`, `ldap_injection.py`, `xxe_injection.py`) are placeholders or for future implementation.
  
  - **`xss/`**:  
    - **`xss_scanner.py`**:  
      Contains the logic for detecting Cross-Site Scripting (XSS) vulnerabilities by injecting various payloads into forms and URL parameters.
  
  - **Additional directories** like **`authentication/`**, **`access_control/`**, **`file_handling/`**, and **`advanced/`** are structured to support scanners for other classes of vulnerabilities and can be extended as needed.

- **`payloads/`**  
  Stores text files with attack payloads (e.g., `sql_injection.txt`, `xss.txt`, `command_injection.txt`) that can be used or extended by the scanners.

- **`results/`**  
  Holds the output of scans (e.g., `scan_results.json`) and logging information (`scanner.log`).

- **`config/`**  
  Contains configuration files such as `scanner_config.json` which defines parameters like maximum threads, request delay, timeout, and the user agent string.

- **`Website/`**  
  A test web application (using Flask) that serves as a controlled environment to test our scanners. It includes:
  - **`test_app.py`**:  
    A vulnerable web application with forms susceptible to SQL injection and XSS.
  - **`test.db`**:  
    An SQLite database used by the test application.

- **`requirements.txt`**  
  Lists all Python dependencies required to run the project.

- **`scanner.py`**  
  The main script that ties everything together. It:
  - Loads configuration.
  - Instantiates the scanners (currently SQL Injection and XSS).
  - Executes the scans concurrently using a thread pool.
  - Saves the scan results.

- **`README.md`**  
  Provides a high-level introduction to the project. (This issue complements the README with in-depth details.)

---

## 3. Key Components & How They Work

- **Core Scanning Framework:**
  - **`BaseScanner`** (in `core/base_scanner.py`):  
    Defines the scanning interface and common behaviors (like making HTTP requests with proper error handling and logging). All specific vulnerability scanners (SQL injection, XSS, etc.) inherit from this class.
  
  - **Utility Functions:**
    - **`URLUtils`**: For URL normalization and validation.
    - **`RequestUtils`**: Uses BeautifulSoup to extract forms from HTML pages, simplifying how scanners process web pages.

- **Vulnerability Scanners:**
  - **SQL Injection Scanner (in `attacks/injection/sql_injection.py`):**
    - Uses several types of payloads to detect vulnerabilities:
      - *Error-Based Injection*: Looks for database error messages in responses.
      - *Boolean-Based Injection*: Compares responses from true and false conditions.
      - *Time-Based Injection*: Measures response delays to infer vulnerabilities.
    
  - **XSS Scanner (in `attacks/xss/xss_scanner.py`):**
    - Injects various XSS payloads into form fields and URL parameters.
    - Checks if the payload is reflected back in the response, indicating a possible vulnerability.

- **Configuration & Concurrency:**
  - **Configuration File (`config/scanner_config.json`)**:  
    Sets parameters such as maximum concurrent threads, delay between requests, timeout settings, and user agent.
  - **Concurrency Handling:**  
    The project uses Python’s `ThreadPoolExecutor` in `scanner.py` to run multiple scanners concurrently, improving performance on larger scans.

---

## 4. Contribution Guidelines

1. **Getting Started:**
   - **Fork and Clone:** Fork the repository and clone it locally.
   - **Install Dependencies:** Run `pip install -r requirements.txt`.
   - **Run the Test App:** Start the test web application with `python Website/test_app.py`. This will launch a Flask server at `http://127.0.0.1:5000`.

2. **Understanding the Codebase:**
   - Review the `README.md` and this issue to get an overview of the project.
   - Examine the files in the `core/` directory to understand common utilities and the base scanner structure.
   - Explore the various modules in the `attacks/` directory to see how specific vulnerabilities are tested.

3. **Adding or Modifying Features:**
   - **New Scanners:** Create a new module in the relevant subdirectory (e.g., `attacks/xss/` or `attacks/injection/`). Inherit from `BaseScanner` and implement your scanning logic.
   - **Updating Existing Scanners:** If you improve a scanning technique or add new payloads, ensure to update both the logic and any related documentation.
   - **Tests:** Use the test web application as a sandbox. Write tests if possible and verify that new contributions do not break existing functionality.

4. **Coding Standards:**
   - Follow PEP8 guidelines for Python code.
   - Write clear, descriptive comments, especially in areas involving complex scanning logic.
   - Update documentation as needed when changes are made.

5. **Submitting Changes:**
   - Create an issue if you find bugs or have suggestions.
   - When ready, submit a pull request with a clear description of your changes, referencing any related issues.

---

## 5. How to Run the Project (Simplified):

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
python scanner.py --url http://127.0.0.1:5000
```

3) Find the vulnerability results in the `scan_results.json` file in you `results/` folder in the root directory.

## 6. Conclusion
This project is built to be modular, extensible, and only for educational purposes at IIIT Sri City @2025.

## 7. **Team details:**
The team for this Internet Security project consists of:
- AJ Harsh Vardhan
- Akshat Mathur
- Sushant Kuril
- Anuroop Reddy

Project Evaluator: Dr. Kamalakanta Sethi 
