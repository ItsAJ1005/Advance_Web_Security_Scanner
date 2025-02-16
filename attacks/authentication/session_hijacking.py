# attacks/authentication/session_hijacking.py
import logging
from typing import Dict
from core.base_scanner import BaseScanner

class SessionHijackingScanner(BaseScanner):
    def __init__(self, target_url: str, config: Dict):

        super().__init__(target_url, config)

    def scan(self) -> Dict:

        results = []
        response = self.make_request(self.target_url)
        if not response:
            return {"session_hijacking": []}

        insecure_cookies = []
        is_https = self.target_url.startswith("https")
        for cookie in response.cookies:
            if "session" in cookie.name.lower():
       
                http_only = cookie._rest.get("HttpOnly", False)
                secure = cookie.secure  
                if not http_only or (is_https and not secure):
                    insecure_cookies.append({
                        "cookie_name": cookie.name,
                        "value": cookie.value,
                        "http_only": http_only,
                        "secure": secure
                    })

        if insecure_cookies:
            results.append({
                "url": self.target_url,
                "vulnerability": "Session Hijacking / Insecure Session Cookie Attributes",
                "details": insecure_cookies,
                "severity": "High"
            })

        return {"session_hijacking": results}
