import time
import logging
from typing import Dict
from core.base_scanner import BaseScanner

class BruteForceScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):

        super().__init__(target_url, config)
        self.login_url = target_url.rstrip('/') + "/login"
        self.credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("user", "password"),
            ("test", "test")
        ]
        self.request_delay = config.get("request_delay", 0.5)

    def scan(self) -> Dict:

        results = []
        for username, password in self.credentials:
            time.sleep(self.request_delay)
            if self.test_brute_force(username, password):
                results.append({
                    "url": self.login_url,
                    "username": username,
                    "password": password,
                    "vulnerability": "Brute Force Authentication Vulnerability",
                    "severity": "High"
                })
                break
        return {"brute_force": results}

    def test_brute_force(self, username: str, password: str) -> bool:

        try:
            data = {"username": username, "password": password}
            response = self.make_request(
                self.login_url,
                method="POST",
                data=data
            )
            if not response:
                return False
      
            if response.status_code == 200 and "invalid" not in response.text.lower():
                logging.info(f"Successful login with {username}:{password}")
                return True
            logging.info(f"Login failed for {username}:{password}")
            return False
        except Exception as e:
            logging.error(f"Error testing brute force for {username}:{password}: {e}")
            return False
