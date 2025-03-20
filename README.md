# Advance Web Security Scanner

## Overview
An advanced web security scanner that checks for OWASP Top 10 vulnerabilities.

## Prerequisites
- Python 3.8+
- Virtual Environment

## ZAP Tool Installation

### Important Note
The ZAP tool is not included in the repository due to its large file size.

### Manual Installation Steps
1. Download OWASP ZAP from the official website:
   [OWASP ZAP Downloads](https://www.zaproxy.org/download/)

2. Create a `zap/` directory in the project root

3. Download the appropriate version for your system:
   - For Linux: `ZAP_Linux.tar.gz`
   - For Windows: `ZAP_Windows.zip`
   - For macOS: `ZAP_MacOS.dmg`

4. Extract the downloaded file into the `zap/` directory

### Automated Download Script
```bash
mkdir -p zap
wget https://github.com/zaproxy/zaproxy/releases/download/v2.11.1/ZAP_2.11.1_Linux.tar.gz -O zap/ZAP_Linux.tar.gz
tar -xzvf zap/ZAP_Linux.tar.gz -C zap
```

## Setup Instructions
1. Clone the repository
2. Create a virtual environment
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
4. Follow ZAP installation steps above
5. Run the application
   ```bash
   python web_interface/app.py
   ```

## Features
- OWASP Top 10 Vulnerability Scanning
- Detailed Vulnerability Reporting
- Web Interface for Scanning

## Contributing
Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
